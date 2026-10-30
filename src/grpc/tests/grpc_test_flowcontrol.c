/*
 * gRPC client flow-control regression test.
 *
 * The test connects a real iwnet gRPC client to a minimal HTTP/2 mock peer.
 * The mock completes the connection preamble, reads and discards client frames,
 * but deliberately delays WINDOW_UPDATE frames. The client queues an upload
 * larger than the initial 64 KiB HTTP/2 flow-control window.
 *
 * With the busy-spin bug the client event loop never leaves the send path:
 * the queued message cannot be sent without a WINDOW_UPDATE, and the poller
 * cannot process the incoming WINDOW_UPDATE. The upload never drains and the
 * test fails. With the fix the client parks until WINDOW_UPDATE arrives and the
 * upload drains.
 */

#include "iwtests.h"
#include "iwn_grpc_client.h"
#include "iwn_poller.h"

#include <iowow/iwlog.h>

#include <pthread.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#define UPLOAD_SIZE        (256 * 1024)
#define WINDOW_INCREMENT   (1024 * 1024)
#define WINDOW_DELAY_MS    300
#define REQUEST_TIMEOUT_MS 10000

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

struct _mock {
  int      listen_fd;
  int      client_fd;
  uint32_t stream_id;
  bool     settings_acked;
  bool     window_sent;
  volatile bool stop;
};

struct _test_result {
  pthread_mutex_t mtx;
  pthread_cond_t  cv;
  bool done;
  bool drained;
  iwrc rc;
};

struct _fixture {
  struct _mock       mock;
  struct iwn_poller *poller;
  struct iwn_grpc_client *client;
  pthread_t mock_thread;
  pthread_t poll_thread;
  char      sock_path[256];
  bool      skip_teardown;
};

static struct _fixture _fx;
static struct _test_result _res = {
  .mtx = PTHREAD_MUTEX_INITIALIZER,
  .cv = PTHREAD_COND_INITIALIZER,
};

static int64_t _now_ms(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (int64_t) ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static int _write_exact(int fd, const void *buf, size_t len) {
  const uint8_t *p = buf;
  while (len) {
    ssize_t n = send(fd, p, len, MSG_NOSIGNAL);
    if (n > 0) {
      p += n;
      len -= n;
      continue;
    }
    if (n < 0 && errno == EINTR) {
      continue;
    }
    return -1;
  }
  return 0;
}

static void _send_frame(
  int fd, uint8_t type, uint8_t flags, uint32_t stream_id,
  const uint8_t *payload, uint32_t len) {
  uint8_t hdr[9] = {
    (uint8_t) (len >> 16),
    (uint8_t) (len >> 8),
    (uint8_t) len,
    type,
    flags,
    (uint8_t) (stream_id >> 24),
    (uint8_t) (stream_id >> 16),
    (uint8_t) (stream_id >> 8),
    (uint8_t) stream_id,
  };
  _write_exact(fd, hdr, sizeof(hdr));
  if (len) {
    _write_exact(fd, payload, len);
  }
}

static void _send_settings(int fd) {
  _send_frame(fd, 4, 0, 0, 0, 0);
}

static void _send_settings_ack(int fd) {
  _send_frame(fd, 4, 1, 0, 0, 0);
}

static void _send_window_update(int fd, uint32_t stream_id, uint32_t increment) {
  uint8_t payload[4] = {
    (uint8_t) (increment >> 24),
    (uint8_t) (increment >> 16),
    (uint8_t) (increment >> 8),
    (uint8_t) increment,
  };
  _send_frame(fd, 8, 0, stream_id, payload, sizeof(payload));
}

/// Reads exactly `len` bytes.
/// Returns 1 on success, 0 on timeout without any received bytes, -1 on EOF/error.
static int _read_exact_to(int fd, void *buf, size_t len) {
  uint8_t *p = buf;
  size_t total = 0;
  while (total < len) {
    ssize_t n = recv(fd, p + total, len - total, 0);
    if (n > 0) {
      total += n;
      continue;
    }
    if (n == 0) {
      return -1;
    }
    if (errno == EINTR) {
      continue;
    }
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      return total == 0 ? 0 : -1;
    }
    return -1;
  }
  return 1;
}

static int _skip_bytes(int fd, uint32_t len, volatile bool *stop) {
  uint8_t tmp[4096];
  while (len) {
    size_t chunk = len < sizeof(tmp) ? len : sizeof(tmp);
    int r = _read_exact_to(fd, tmp, chunk);
    if (r > 0) {
      len -= chunk;
      continue;
    }
    if (r < 0) {
      return -1;
    }
    if (stop && *stop) {
      return -1;
    }
  }
  return 0;
}

static void* _mock_thread(void *arg) {
  struct _mock *m = arg;
  int fd = -1;

  while (!m->stop) {
    struct pollfd pfd = {
      .fd = m->listen_fd,
      .events = POLLIN,
    };
    int pr = poll(&pfd, 1, 50);
    if (pr > 0 && (pfd.revents & POLLIN)) {
      fd = accept(m->listen_fd, 0, 0);
      break;
    }
    if (pr < 0 && errno != EINTR) {
      return 0;
    }
  }
  if (fd < 0) {
    return 0;
  }
  m->client_fd = fd;

  struct timeval tv = { .tv_sec = 0, .tv_usec = 50000 };
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

  // A real server sends SETTINGS as its first frame.
  _send_settings(fd);

  int64_t start = _now_ms();
  uint8_t preface[24];
  for ( ; ; ) {
    int r = _read_exact_to(fd, preface, sizeof(preface));
    if (r > 0) {
      break;
    }
    if (r < 0 || m->stop || _now_ms() - start > 3000) {
      goto done;
    }
  }

  for ( ; ; ) {
    if (m->stop) {
      break;
    }

    uint8_t hdr[9];
    int r = _read_exact_to(fd, hdr, sizeof(hdr));
    if (r < 0) {
      break;
    }
    if (r > 0) {
      uint32_t len = ((uint32_t) hdr[0] << 16) | ((uint32_t) hdr[1] << 8) | hdr[2];
      uint8_t type = hdr[3];
      uint8_t flags = hdr[4];
      uint32_t stream_id = ((uint32_t) hdr[5] << 24) | ((uint32_t) hdr[6] << 16)
                           | ((uint32_t) hdr[7] << 8) | hdr[8];

      if (type == 1 && stream_id && !m->stream_id) {
        m->stream_id = stream_id;
      }
      if (_skip_bytes(fd, len, &m->stop)) {
        break;
      }
      if (type == 4 && !(flags & 1) && !m->settings_acked) {
        _send_settings_ack(fd);
        m->settings_acked = true;
      }
    }

    if (!m->window_sent && _now_ms() - start >= WINDOW_DELAY_MS) {
      uint32_t stream_id = m->stream_id ? m->stream_id : 1;
      _send_window_update(fd, 0, WINDOW_INCREMENT);
      _send_window_update(fd, stream_id, WINDOW_INCREMENT);
      m->window_sent = true;
    }
  }

done:
  close(fd);
  m->client_fd = -1;
  return 0;
}

static void _on_outgoing_messages_queue_drained(struct iwn_grpc_req_ctx *ctx) {
  struct _test_result *res = ctx->spec.user_data;
  pthread_mutex_lock(&res->mtx);
  res->drained = true;
  res->done = true;
  pthread_cond_signal(&res->cv);
  pthread_mutex_unlock(&res->mtx);
}

static void _on_error(struct iwn_grpc_req_ctx *ctx) {
  struct _test_result *res = ctx->spec.user_data;
  pthread_mutex_lock(&res->mtx);
  if (!res->rc) {
    res->rc = ctx->rc;
  }
  pthread_mutex_unlock(&res->mtx);
}

static void _on_destroy(const struct iwn_grpc_req_ctx *ctx) {
  struct _test_result *res = ctx->spec.user_data;
  pthread_mutex_lock(&res->mtx);
  res->done = true;
  pthread_cond_signal(&res->cv);
  pthread_mutex_unlock(&res->mtx);
}

static iwrc _wait_drained(void) {
  iwrc rc = 0;
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  ts.tv_sec += REQUEST_TIMEOUT_MS / 1000;

  pthread_mutex_lock(&_res.mtx);
  while (!_res.done) {
    int rci = pthread_cond_timedwait(&_res.cv, &_res.mtx, &ts);
    if (rci == ETIMEDOUT) {
      rc = IW_ERROR_OPERATION_TIMEOUT;
      break;
    }
  }
  pthread_mutex_unlock(&_res.mtx);
  return rc;
}

static iwrc _mock_listen(struct _mock *m) {
  iwrc rc = 0;
  struct sockaddr_un sa = { .sun_family = AF_UNIX };

  mkdir("/tmp/pi", 0700);
  snprintf(_fx.sock_path, sizeof(_fx.sock_path), "/tmp/pi/iwn_grpc_fc_%d.sock", (int) getpid());
  unlink(_fx.sock_path);

  size_t path_len = strlen(_fx.sock_path);
  if (path_len >= sizeof(sa.sun_path)) {
    return IW_ERROR_INVALID_ARGS;
  }
  memcpy(sa.sun_path, _fx.sock_path, path_len + 1);

  RCN(finish, m->listen_fd = socket(AF_UNIX, SOCK_STREAM, 0));
  RCN(finish, bind(m->listen_fd, (void*) &sa, sizeof(sa)));
  RCN(finish, listen(m->listen_fd, 1));

  int flags = fcntl(m->listen_fd, F_GETFL, 0);
  RCN(finish, flags);
  RCN(finish, fcntl(m->listen_fd, F_SETFL, flags | O_NONBLOCK));

finish:
  return rc;
}

static iwrc _fixture_start(void) {
  iwrc rc = 0;
  char url[300];

  signal(SIGPIPE, SIG_IGN);
  _fx.mock.listen_fd = -1;
  _fx.mock.client_fd = -1;

  RCC(rc, finish, _mock_listen(&_fx.mock));
  int rci = pthread_create(&_fx.mock_thread, 0, _mock_thread, &_fx.mock);
  if (rci) {
    rc = iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rci);
    goto finish;
  }

  snprintf(url, sizeof(url), "grpc+socket://%s", _fx.sock_path);
  RCC(rc, finish, iwn_grpc_init());
  RCC(rc, finish, iwn_poller_create(2, 1, &_fx.poller));

  struct iwn_grpc_client_spec cspec = {
    .url = url,
    .poller = _fx.poller,
  };
  RCC(rc, finish, iwn_grpc_client_open(&cspec, &_fx.client));
  RCC(rc, finish, iwn_poller_poll_in_thread(_fx.poller, "grpc-flowcontrol", &_fx.poll_thread));

finish:
  return rc;
}

static void _fixture_stop(void) {
  if (_fx.skip_teardown) {
    // The poller thread is stuck in the old busy-spin loop. Let the process
    // exit terminate it instead of hanging on pthread_join().
    return;
  }

  if (_fx.client) {
    iwn_grpc_client_close(_fx.client);
  }
  if (_fx.poller) {
    if (_fx.poll_thread) {
      iwn_poller_shutdown_request(_fx.poller);
      pthread_join(_fx.poll_thread, 0);
    }
    iwn_poller_destroy(&_fx.poller);
  }

  _fx.mock.stop = true;
  if (_fx.mock.client_fd > -1) {
    shutdown(_fx.mock.client_fd, SHUT_RDWR);
  }
  if (_fx.mock.listen_fd > -1) {
    shutdown(_fx.mock.listen_fd, SHUT_RDWR);
  }
  if (_fx.mock_thread) {
    pthread_join(_fx.mock_thread, 0);
  }
  if (_fx.mock.listen_fd > -1) {
    close(_fx.mock.listen_fd);
    _fx.mock.listen_fd = -1;
  }
  if (_fx.sock_path[0]) {
    unlink(_fx.sock_path);
  }
}

static int _suite_init(void) {
  iwrc rc = _fixture_start();
  if (rc) {
    iwlog_ecode_error3(rc);
    _fixture_stop();
  }
  return rc;
}

static void _suite_cleanup(void) {
  _fixture_stop();
}

static void test_flow_control_block(void) {
  iwrc rc = 0;
  char *payload = malloc(UPLOAD_SIZE);
  IW_TEST_ASSERT_FATAL(payload);
  memset(payload, 'x', UPLOAD_SIZE);

  struct iwn_val msg = {
    .buf = payload,
    .len = UPLOAD_SIZE,
  };
  struct iwn_grpc_req_spec rspec = {
    .client = _fx.client,
    .path = "/test.FlowControl/Upload",
    .user_data = &_res,
    .on_outgoing_messages_queue_drained = _on_outgoing_messages_queue_drained,
    .on_error = _on_error,
    .on_destroy = _on_destroy,
  };

  RCC(rc, finish, iwn_grpc_client_request_open(&rspec, &msg, 0, 0));

  rc = _wait_drained();
  if (rc) {
    // Without the fix the poller is stuck in the client send loop.
    _fx.skip_teardown = true;
  }
  IW_TEST_ASSERT_EQUAL(rc, 0);
  IW_TEST_ASSERT(_res.drained);
  IW_TEST_ASSERT_EQUAL(_res.rc, 0);

finish:
  free(payload);
  IW_TEST_ASSERT_EQUAL(rc, 0);
}

int main(int argc, char *argv[]) {
  static const struct iw_test_case cases[] = {
    IW_TEST_CASE(test_flow_control_block),
  };
  return iw_test_run(argc, argv, IW_TEST_SUITE("grpc_flow_control", cases, _suite_init, _suite_cleanup));
}

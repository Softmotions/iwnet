/*
 * Regression test for the poller adapter `arm()` contract of the TLS adapters.
 *
 * `iwn_poller_adapter::arm()` requested from inside an adapter event callback must
 * reach the poller: the poller records such a request and applies it when the
 * callback returns. The TLS adapters (s2n, BearSSL) used to silently drop it, which
 * stalled the gRPC client — its deferred GOAWAY handling armed `IWN_POLLOUT` while
 * nothing else re-armed the fd, so the poll loop never woke up again.
 *
 * How the test works:
 * - an in-process TLS HTTP server is created on a unix socket and only serves as the
 *   TLS peer (it never receives a request);
 * - a connected socket is wrapped into a TLS client poller adapter. The adapter
 *   completes the TLS handshake and then delivers `IWN_POLLOUT` to the consumer;
 * - on that callback the consumer arms `IWN_POLLOUT` and returns `0`, i.e. it does
 *   not request the event through the return value, and verifies with
 *   ::iwn_poller_armed_events() that the request was recorded by the poller.
 *
 * A TLS adapter which drops `arm()` inside its own dispatch leaves nothing recorded
 * and the test fails. Applying/delivering the armed event itself is not asserted:
 * an always writable socket produces `IWN_POLLOUT` callbacks for other reasons too,
 * while the recorded request is exactly what the dropped-`arm()` defect breaks.
 */

#include "iwtests.h"
#include "iwn_http_server.h"
#include "iwn_tls_poller_adapter.h"
#include "iwn_tests_tls.h"

#include <iowow/iwlog.h>

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

static struct iwn_poller *poller;
static pthread_mutex_t mtx = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cnd = PTHREAD_COND_INITIALIZER;
static bool arm_called;
static bool arm_recorded;
static bool failed;
static bool done;

static bool _request_handler(struct iwn_http_req *req) {
  iwn_http_response_body_set(req, "unused", -1, 0);
  return iwn_http_response_end(req) == 0;
}

static void _finish(bool ok) {
  pthread_mutex_lock(&mtx);
  if (ok) {
    arm_recorded = true;
  } else {
    failed = true;
  }
  done = true;
  pthread_cond_signal(&cnd);
  pthread_mutex_unlock(&mtx);
  if (poller) {
    iwn_poller_shutdown_request(poller);
  }
}

static int64_t _on_event(struct iwn_poller_adapter *pa, void *user_data, uint32_t events) {
  if (!(events & IWN_POLLOUT)) {
    return 0;
  }
  pthread_mutex_lock(&mtx);
  bool first = !arm_called;
  arm_called = true;
  pthread_mutex_unlock(&mtx);
  if (!first) {
    return 0;
  }
  // Nothing has been armed for this fd at this point.
  uint32_t before = iwn_poller_armed_events(poller, pa->fd);
  bool ok = pa->arm(pa, IWN_POLLOUT) == 0;
  uint32_t after = iwn_poller_armed_events(poller, pa->fd);
  _finish(ok && before == 0 && (after & IWN_POLLOUT));
  return 0; // Deliberately not requested through the return value.
}

static iwrc _connect_unix(const char *path, int *out_fd) {
  struct sockaddr_un addr = { .sun_family = AF_UNIX };
  size_t path_len = strlen(path);
  if (path_len >= sizeof(addr.sun_path)) {
    return IW_ERROR_INVALID_ARGS;
  }
  memcpy(addr.sun_path, path, path_len + 1);
  int fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0) {
    return iwrc_set_errno(IW_ERROR_ERRNO, errno);
  }
  if (connect(fd, (void*) &addr, sizeof(addr)) != 0) {
    iwrc rc = iwrc_set_errno(IW_ERROR_ERRNO, errno);
    close(fd);
    return rc;
  }
  int flags = fcntl(fd, F_GETFL, 0);
  if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0) {
    iwrc rc = iwrc_set_errno(IW_ERROR_ERRNO, errno);
    close(fd);
    return rc;
  }
  *out_fd = fd;
  return 0;
}

static void test_adapter_arm_from_callback(void) {
  iwrc rc = 0;
  int fd = -1;
  int server_fd = -1;
  bool got_called = false;
  bool got_recorded = false;
  bool got_failed = false;
  bool got_done = false;
  char sock_path[64];
  char lock_path[80];
  char listen[128];
  struct timespec deadline;

  snprintf(sock_path, sizeof(sock_path), "/tmp/iwnet_tls_arm_%d.sock", (int) getpid());
  snprintf(lock_path, sizeof(lock_path), "%s.lock", sock_path);
  snprintf(listen, sizeof(listen), "socket://%s", sock_path);
  unlink(sock_path);
  unlink(lock_path);

  RCC(rc, finish, iwn_poller_create(2, 1, &poller));
  RCC(rc, finish, iwn_http_server_create(&(struct iwn_http_server_spec) {
    .listen = listen,
    .poller = poller,
    .request_handler = _request_handler,
    .request_timeout_sec = -1,
    .request_timeout_keepalive_sec = -1,
    .ssl = {
      .tls_impl = iwn_test_tls_impl(),
      .certs = "./server-ecdsacert.pem",
      .certs_len = -1,
      .private_key = "./server-eckey.pem",
      .private_key_len = -1,
    },
  }, &server_fd));
  RCC(rc, finish, _connect_unix(sock_path, &fd));
  RCC(rc, finish, iwn_tls_client_poller_adapter(&(struct iwn_tls_client_poller_adapter_spec) {
    .tls_impl = iwn_test_tls_impl(),
    .poller = poller,
    .on_event = _on_event,
    .timeout_sec = -1,
    .events = IWN_POLLOUT, // The handshake starts with a writable socket.
    .events_mod = IWN_POLLET,
    .fd = fd,
    .verify_peer = false,
    .verify_host = false,
  }));
  fd = -1; // Owned by the poller adapter from now on

  RCC(rc, finish, iwn_poller_poll_in_thread(poller, "tls-arm", 0));

  clock_gettime(CLOCK_REALTIME, &deadline);
  deadline.tv_sec += 3;

  pthread_mutex_lock(&mtx);
  while (!done) {
    if (pthread_cond_timedwait(&cnd, &mtx, &deadline) == ETIMEDOUT) {
      break;
    }
  }
  got_called = arm_called;
  got_recorded = arm_recorded;
  got_failed = failed;
  got_done = done;
  pthread_mutex_unlock(&mtx);

finish:
  if (fd > -1) {
    close(fd);
  }
  if (rc) {
    iwlog_ecode_error3(rc);
  }
  if (poller) {
    iwn_poller_shutdown_request(poller);
    iwn_poller_destroy(&poller);
  }
  unlink(sock_path);
  unlink(lock_path);

  IW_TEST_ASSERT_EQUAL(rc, 0);
  if (!rc) {
    IW_TEST_ASSERT_TRUE(got_done);
    IW_TEST_ASSERT_TRUE(got_called);
    IW_TEST_ASSERT_FALSE(got_failed);
    IW_TEST_ASSERT_TRUE(got_recorded);
  }
}

int main(int argc, char *argv[]) {
  static const struct iw_test_case cases[] = {
    IW_TEST_CASE(test_adapter_arm_from_callback),
  };
  iwlog_init();
  return iw_test_run(argc, argv, IW_TEST_SUITE("tls_arm", cases, 0, 0));
}

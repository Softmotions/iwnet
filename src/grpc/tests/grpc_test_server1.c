/*
 * gRPC server <-> client integration test.
 *
 * A gRPC server and client run in the same process over a UNIX domain socket.
 * The suite starts one poller, server and client, then runs one test case per
 * gRPC mode:
 *   - unary
 *   - server streaming
 *   - client streaming
 *   - bidirectional streaming
 * plus an unknown-path error case.
 *
 * Server handlers dispatch by request path. The client side collects response
 * messages and completion (on_destroy) is synchronized with a condition
 * variable, so each case verifies the complete response before it returns.
 */

#include "iwtests.h"
#include "iwn_grpc_client.h"
#include "iwn_grpc_server.h"
#include "iwn_poller.h"

#include <iowow/iwlog.h>

#include <pthread.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define _ACC_CAP 512

struct _fixture {
  struct iwn_poller      *poller;
  struct iwn_grpc_server *server;
  struct iwn_grpc_client *client;
  pthread_t poll_thread;
  char      sock_path[256];
};

static struct _fixture _fx;

/// Per-request server state for client streaming.
struct _srv_req_data {
  char   acc[_ACC_CAP];
  size_t len;
};

/// Per-request client result.
struct _req_result {
  pthread_mutex_t mtx;
  pthread_cond_t  cv;
  char   data[_ACC_CAP];
  size_t data_len;
  int    num_messages;
  iwrc   rc;
  bool   closed;
  bool   done;
};

///////////////////////////////////////////////////////////////////////////
//                             Server handlers                             //
///////////////////////////////////////////////////////////////////////////

static iwrc _srv_on_request(struct iwn_grpc_server_req *req) {
  if (!req->path) {
    return GRPC_ERROR_NOT_FOUND;
  }
  if (  strcmp(req->path, "/test.Echo/Unary") == 0
     || strcmp(req->path, "/test.Echo/ServerStream") == 0
     || strcmp(req->path, "/test.Echo/BidiStream") == 0) {
    return 0;
  }
  if (strcmp(req->path, "/test.Echo/ClientStream") == 0) {
    struct _srv_req_data *d = calloc(1, sizeof(*d));
    if (!d) {
      return IW_ERROR_ALLOC;
    }
    req->user_data = d;
    return 0;
  }
  return GRPC_ERROR_UNIMPLEMENTED;
}

static void _srv_on_message(struct iwn_grpc_server_msg *msg, bool *out_continue) {
  const char *path = msg->req->path;

  if (strcmp(path, "/test.Echo/ServerStream") == 0) {
    return;
  }

  if (strcmp(path, "/test.Echo/ClientStream") == 0) {
    struct _srv_req_data *d = msg->req->user_data;
    if (!d || d->len + msg->msg.len > sizeof(d->acc)) {
      IW_TEST_FAILF("Server accumulator overflow");
      *out_continue = false;
      return;
    }
    if (msg->msg.len) {
      memcpy(d->acc + d->len, msg->msg.buf, msg->msg.len);
      d->len += msg->msg.len;
    }
    return;
  }

  // Unary and bidirectional streaming: echo every incoming message.
  iwrc rc = iwn_grpc_server_req_write_message(msg->req, &msg->msg, msg->compressed);
  if (rc) {
    IW_TEST_FAILF("Server write message failed: %d", rc);
    *out_continue = false;
  }
}

static iwrc _srv_write(struct iwn_grpc_server_req *req, const char *buf, size_t len) {
  struct iwn_val msg = {
    .buf = (char*) buf,
    .len = len,
  };
  return iwn_grpc_server_req_write_message(req, &msg, false);
}

static void _srv_on_request_end(struct iwn_grpc_server_req *req) {
  iwrc rc = 0;

  if (strcmp(req->path, "/test.Echo/ServerStream") == 0) {
    static const char *msgs[] = { "s1", "s2", "s3" };
    for (size_t i = 0; i < sizeof(msgs) / sizeof(msgs[0]); ++i) {
      rc = _srv_write(req, msgs[i], strlen(msgs[i]));
      if (rc) {
        break;
      }
    }
  } else if (strcmp(req->path, "/test.Echo/ClientStream") == 0) {
    struct _srv_req_data *d = req->user_data;
    if (d) {
      rc = _srv_write(req, d->acc, d->len);
    }
  }

  if (!rc) {
    rc = iwn_grpc_server_req_end(req, 0, 0);
  }
  if (rc) {
    IW_TEST_FAILF("Server request end failed: %d", rc);
  }
}

static void _srv_on_request_destroy(const struct iwn_grpc_server_req *req) {
  free(req->user_data);
}

///////////////////////////////////////////////////////////////////////////
//                          Client result handling                       //
///////////////////////////////////////////////////////////////////////////

static void _res_init(struct _req_result *res) {
  memset(res, 0, sizeof(*res));
  pthread_mutex_init(&res->mtx, 0);
  pthread_cond_init(&res->cv, 0);
}

static void _res_destroy(struct _req_result *res) {
  pthread_mutex_destroy(&res->mtx);
  pthread_cond_destroy(&res->cv);
}

static void _cli_on_message(struct iwn_grpc_req_message *msg, bool *out_continue) {
  struct _req_result *res = msg->ctx.spec.user_data;
  pthread_mutex_lock(&res->mtx);
  if (res->data_len + msg->msg.len > sizeof(res->data)) {
    res->rc = IW_ERROR_OVERFLOW;
  } else {
    if (msg->msg.len) {
      memcpy(res->data + res->data_len, msg->msg.buf, msg->msg.len);
      res->data_len += msg->msg.len;
    }
    res->num_messages++;
  }
  pthread_mutex_unlock(&res->mtx);
}

static void _cli_on_error(struct iwn_grpc_req_ctx *ctx) {
  struct _req_result *res = ctx->spec.user_data;
  pthread_mutex_lock(&res->mtx);
  if (!res->rc) {
    res->rc = ctx->rc;
  }
  pthread_mutex_unlock(&res->mtx);
}

static void _cli_on_closed(const struct iwn_grpc_req_ctx *ctx) {
  struct _req_result *res = ctx->spec.user_data;
  pthread_mutex_lock(&res->mtx);
  res->closed = true;
  pthread_mutex_unlock(&res->mtx);
}

static void _cli_on_destroy(const struct iwn_grpc_req_ctx *ctx) {
  struct _req_result *res = ctx->spec.user_data;
  pthread_mutex_lock(&res->mtx);
  res->done = true;
  pthread_cond_signal(&res->cv);
  pthread_mutex_unlock(&res->mtx);
}

static iwrc _res_wait(struct _req_result *res) {
  iwrc rc = 0;
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  ts.tv_sec += 10;

  pthread_mutex_lock(&res->mtx);
  while (!res->done) {
    int rci = pthread_cond_timedwait(&res->cv, &res->mtx, &ts);
    if (rci == ETIMEDOUT) {
      rc = IW_ERROR_OPERATION_TIMEOUT;
      break;
    }
  }
  pthread_mutex_unlock(&res->mtx);
  return rc;
}

static iwrc _res_open(
  struct _req_result   *res,
  const char           *path,
  const struct iwn_val *msg,
  bool                  client_streaming,
  uint32_t             *out_req_id) {
  struct iwn_grpc_req_spec spec = {
    .client = _fx.client,
    .path = path,
    .client_streaming = client_streaming,
    .user_data = res,
    .on_message = _cli_on_message,
    .on_error = _cli_on_error,
    .on_closed = _cli_on_closed,
    .on_destroy = _cli_on_destroy,
  };
  return iwn_grpc_client_request_open(&spec, msg, 0, out_req_id);
}

///////////////////////////////////////////////////////////////////////////
//                              Test cases                                 //
///////////////////////////////////////////////////////////////////////////

static void test_unary(void) {
  struct _req_result res;
  struct iwn_val msg = { .buf = "hello", .len = 5 };
  _res_init(&res);

  iwrc rc = _res_open(&res, "/test.Echo/Unary", &msg, false, 0);
  IW_TEST_ASSERT_EQUAL(rc, 0);
  if (!rc) {
    IW_TEST_ASSERT_EQUAL(_res_wait(&res), 0);
    IW_TEST_ASSERT(res.closed);
    IW_TEST_ASSERT_EQUAL(res.rc, 0);
    IW_TEST_ASSERT_EQUAL(res.num_messages, 1);
    IW_TEST_ASSERT(res.data_len == msg.len);
    IW_TEST_ASSERT(!memcmp(res.data, msg.buf, msg.len));
  }

  _res_destroy(&res);
}

static void test_server_streaming(void) {
  struct _req_result res;
  struct iwn_val msg = { .buf = "start", .len = 5 };
  _res_init(&res);

  iwrc rc = _res_open(&res, "/test.Echo/ServerStream", &msg, false, 0);
  IW_TEST_ASSERT_EQUAL(rc, 0);
  if (!rc) {
    IW_TEST_ASSERT_EQUAL(_res_wait(&res), 0);
    IW_TEST_ASSERT(res.closed);
    IW_TEST_ASSERT_EQUAL(res.rc, 0);
    IW_TEST_ASSERT_EQUAL(res.num_messages, 3);
    IW_TEST_ASSERT(res.data_len == 6);
    IW_TEST_ASSERT(!memcmp(res.data, "s1s2s3", 6));
  }

  _res_destroy(&res);
}

static void test_client_streaming(void) {
  struct _req_result res;
  uint32_t req_id = 0;
  struct iwn_val msgs[] = {
    { .buf = "a", .len = 1 },
    { .buf = "b", .len = 1 },
    { .buf = "c", .len = 1 },
  };
  _res_init(&res);

  iwrc rc = _res_open(&res, "/test.Echo/ClientStream", &msgs[0], true, &req_id);
  IW_TEST_ASSERT_EQUAL(rc, 0);
  if (!rc) {
    struct iwn_grpc_req_ctx rctx;
    if (!iwn_grpc_client_acquire_request_ctx(_fx.client, req_id, &rctx)) {
      IW_TEST_FAILF("Failed to acquire request context");
      rc = IW_ERROR_FAIL;
    } else {
      rc = iwn_grpc_client_stream_next_message(&rctx, &msgs[1], false);
      if (!rc) {
        rc = iwn_grpc_client_stream_next_message(&rctx, &msgs[2], true);
      }
      iwn_grpc_client_release_request_ctx(&rctx);
    }
    IW_TEST_ASSERT_EQUAL(rc, 0);
  }
  if (!rc) {
    IW_TEST_ASSERT_EQUAL(_res_wait(&res), 0);
    IW_TEST_ASSERT(res.closed);
    IW_TEST_ASSERT_EQUAL(res.rc, 0);
    IW_TEST_ASSERT_EQUAL(res.num_messages, 1);
    IW_TEST_ASSERT(res.data_len == 3);
    IW_TEST_ASSERT(!memcmp(res.data, "abc", 3));
  }

  _res_destroy(&res);
}

static void test_bidi_streaming(void) {
  struct _req_result res;
  uint32_t req_id = 0;
  struct iwn_val msgs[] = {
    { .buf = "a", .len = 1 },
    { .buf = "b", .len = 1 },
    { .buf = "c", .len = 1 },
  };
  _res_init(&res);

  iwrc rc = _res_open(&res, "/test.Echo/BidiStream", &msgs[0], true, &req_id);
  IW_TEST_ASSERT_EQUAL(rc, 0);
  if (!rc) {
    struct iwn_grpc_req_ctx rctx;
    if (!iwn_grpc_client_acquire_request_ctx(_fx.client, req_id, &rctx)) {
      IW_TEST_FAILF("Failed to acquire request context");
      rc = IW_ERROR_FAIL;
    } else {
      rc = iwn_grpc_client_stream_next_message(&rctx, &msgs[1], false);
      if (!rc) {
        rc = iwn_grpc_client_stream_next_message(&rctx, &msgs[2], true);
      }
      iwn_grpc_client_release_request_ctx(&rctx);
    }
    IW_TEST_ASSERT_EQUAL(rc, 0);
  }
  if (!rc) {
    IW_TEST_ASSERT_EQUAL(_res_wait(&res), 0);
    IW_TEST_ASSERT(res.closed);
    IW_TEST_ASSERT_EQUAL(res.rc, 0);
    IW_TEST_ASSERT_EQUAL(res.num_messages, 3);
    IW_TEST_ASSERT(res.data_len == 3);
    IW_TEST_ASSERT(!memcmp(res.data, "abc", 3));
  }

  _res_destroy(&res);
}

static void test_unknown_path(void) {
  struct _req_result res;
  struct iwn_val msg = { .buf = "hello", .len = 5 };
  _res_init(&res);

  iwrc rc = _res_open(&res, "/test.Echo/Missing", &msg, false, 0);
  IW_TEST_ASSERT_EQUAL(rc, 0);
  if (!rc) {
    IW_TEST_ASSERT_EQUAL(_res_wait(&res), 0);
    IW_TEST_ASSERT(res.closed);
    IW_TEST_ASSERT_EQUAL(res.rc, GRPC_ERROR_UNIMPLEMENTED);
    IW_TEST_ASSERT_EQUAL(res.num_messages, 0);
  }

  _res_destroy(&res);
}

///////////////////////////////////////////////////////////////////////////
//                                Fixture                                  //
///////////////////////////////////////////////////////////////////////////

static iwrc _fixture_start(void) {
  iwrc rc = 0;
  char url[300];

  signal(SIGPIPE, SIG_IGN);
  mkdir("/tmp/pi", 0700);
  snprintf(_fx.sock_path, sizeof(_fx.sock_path), "/tmp/pi/iwn_grpc_test_%d.sock", (int) getpid());
  unlink(_fx.sock_path);
  snprintf(url, sizeof(url), "grpc+socket://%s", _fx.sock_path);

  RCC(rc, finish, iwn_grpc_init());
  RCC(rc, finish, iwn_poller_create(2, 1, &_fx.poller));

  struct iwn_grpc_server_spec sspec = {
    .url = url,
    .poller = _fx.poller,
    .on_request = _srv_on_request,
    .on_message = _srv_on_message,
    .on_request_end = _srv_on_request_end,
    .on_request_destroy = _srv_on_request_destroy,
  };
  RCC(rc, finish, iwn_grpc_server_open(&sspec, &_fx.server));

  struct iwn_grpc_client_spec cspec = {
    .url = url,
    .poller = _fx.poller,
  };
  RCC(rc, finish, iwn_grpc_client_open(&cspec, &_fx.client));
  RCC(rc, finish, iwn_poller_poll_in_thread(_fx.poller, "grpc-test", &_fx.poll_thread));

finish:
  return rc;
}

static void _fixture_stop(void) {
  if (_fx.client) {
    iwn_grpc_client_close(_fx.client);
  }
  if (_fx.server) {
    iwn_grpc_server_close(_fx.server);
  }
  if (_fx.poller) {
    if (_fx.poll_thread) {
      iwn_poller_shutdown_request(_fx.poller);
      pthread_join(_fx.poll_thread, 0);
    }
    iwn_poller_destroy(&_fx.poller);
  }
  if (_fx.sock_path[0]) {
    unlink(_fx.sock_path);
  }
  memset(&_fx, 0, sizeof(_fx));
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

int main(int argc, char *argv[]) {
  static const struct iw_test_case cases[] = {
    IW_TEST_CASE(test_unary),
    IW_TEST_CASE(test_server_streaming),
    IW_TEST_CASE(test_client_streaming),
    IW_TEST_CASE(test_bidi_streaming),
    IW_TEST_CASE(test_unknown_path),
  };
  return iw_test_run(argc, argv, IW_TEST_SUITE("grpc_server", cases, _suite_init, _suite_cleanup));
}

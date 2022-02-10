
#include "utils/tests.h"
#include "http_server.h"

#include <iowow/iwxstr.h>
#include <iowow/iwconv.h>

#include <pthread.h>
#include <signal.h>
#include <string.h>
#include <limits.h>
#include <errno.h>

static struct iwn_poller *poller;

#define STATE_SERVER_DISPOSED  0x01U
#define STATE_CLOSED_ON_SIGNAL 0x02U

static uint32_t state;

static void _on_signal(int signo) {
  state |= STATE_CLOSED_ON_SIGNAL;
  if (poller) {
    iwn_poller_shutdown_request(poller);
  }
}

static void _server_on_dispose(const struct iwn_http_server *srv) {
  state |= STATE_SERVER_DISPOSED;
}

static bool _chunk_req_cb(struct iwn_http_req *req) {
  IWXSTR *xstr = req->user_data;
  IWN_ASSERT_FATAL(xstr);
  struct iwn_val val = iwn_http_request_chunk_get(req);
  if (val.len > 0) {
    iwrc rc = iwxstr_cat(xstr, val.buf, val.len);
    IWN_ASSERT_FATAL(rc == 0);
    iwn_http_request_chunk_next(req, _chunk_req_cb);
  } else {
    char *body = iwxstr_ptr(xstr);
    size_t body_len = iwxstr_size(xstr);
    iwn_http_response_body_set(req, body, body_len, 0);
    iwrc rc = iwn_http_response_end(req);
    IWN_ASSERT(rc == 0);
  }
  return true;
}

static bool _chunk_resp_cb(struct iwn_http_req *req) {
  int chunk_count = (int) (intptr_t) req->user_data;
  ++chunk_count;
  req->user_data = (void*) (intptr_t) chunk_count;

  char *cdata = 0;
  switch (chunk_count) {
    case 1:
      cdata = "\ne6276e6e-573c-4edb-b840-ae00680a5578";
      break;
    case 2:
      cdata = "\n097a5dd6-8df3-4d43-b3f1-0a01ea1d9943";
      break;
  }
  if (cdata) {
    iwrc rc = iwn_http_response_chunk_write(req, cdata, -1, _chunk_resp_cb);
    IWN_ASSERT(rc == 0);
  } else {
    iwrc rc = iwn_http_response_chunk_end(req);
    IWN_ASSERT(rc == 0);
  }
  return true;
}

static void _on_chunk_req_destroy(struct iwn_http_req *req) {
  IWXSTR *xstr = req->user_data;
  if (xstr) {
    iwxstr_destroy(xstr);
  }
}

static bool _request_handler(struct iwn_http_req *req) {
  iwrc rc = 0;

  if (iwn_http_request_target_is(req, "/empty", -1)) {
    ; // No body
  } else if (iwn_http_request_target_is(req, "/echo", -1)) {
    struct iwn_val val = iwn_http_request_body(req);
    RCC(rc, finish, iwn_http_response_header_set(req, "content-type", "text/plain", -1));
    iwn_http_response_body_set(req, val.buf, val.len, 0);
  } else if (iwn_http_request_target_is(req, "/header", -1)) {
    struct iwn_val val = iwn_http_request_header_get(req, "X-Foo", -1);
    iwn_http_response_body_set(req, val.buf, val.len, 0);
  } else if (iwn_http_request_target_is(req, "/large", -1)) {
    IWN_ASSERT(iwn_http_request_is_streamed(req));
    IWXSTR *xstr;
    RCA(xstr = iwxstr_new(), finish);
    req->user_data = xstr;
    req->on_request_dispose = _on_chunk_req_destroy;
    iwn_http_request_chunk_next(req, _chunk_req_cb);
    goto finish;
  } else if (iwn_http_request_target_is(req, "/chunked", -1)) {
    RCC(rc, finish, iwn_http_response_header_set(req, "content-type", "text/plain", -1));
    RCC(rc, finish, iwn_http_response_chunk_write(req, "\n4cd009fb-dceb-4907-a6be-dd05c3f052b3",
                                                  -1, _chunk_resp_cb));
    goto finish;
  } else {
    RCC(rc, finish, iwn_http_response_header_set(req, "content-type", "text/plain", -1));
    iwn_http_response_body_set(req, "4afb7857-6b21-4a25-ae47-0852ebc47014", -1, 0);
  }

  rc = iwn_http_response_end(req);

finish:
  if (rc) {
    iwlog_ecode_error3(rc);
  }
  return true;
}

int main(int argc, char *argv[]) {
  iwrc rc = 0;
  iwlog_init();

  signal(SIGPIPE, SIG_IGN);
  signal(SIGHUP, SIG_IGN);
  signal(SIGALRM, SIG_IGN);
  signal(SIGUSR1, SIG_IGN);
  signal(SIGUSR2, SIG_IGN);
  if (signal(SIGTERM, _on_signal) == SIG_ERR) {
    return EXIT_FAILURE;
  }
  if (signal(SIGINT, _on_signal) == SIG_ERR) {
    return EXIT_FAILURE;
  }

  bool ssl = false;
  int port = 9292;
  int nthreads = 1;
  int oneshot = 1;

  for (int i = 0; i < argc; ++i) {
    if (strcmp(argv[i], "--ssl") == 0) {
      ssl = true;
    } else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
      port = iwatoi(argv[i + 1]);
    } else if (strcmp(argv[i], "--poll-threads") == 0 && i + 1 < argc) {
      nthreads = iwatoi(argv[i + 1]);
    } else if (strcmp(argv[i], "--poll-oneshot-events") == 0 && i + 1 < argc) {
      oneshot = iwatoi(argv[i + 1]);
    }
  }

  RCC(rc, finish, iwn_poller_create(nthreads, oneshot, &poller));

  struct iwn_http_server_spec spec = {
    .listen                        = "localhost",
    .port                          = port,
    .poller                        = poller,
    .user_data                     = poller,
    .request_handler               = _request_handler,
    .on_server_dispose             = _server_on_dispose,
    .request_timeout_sec           = -1,
    .request_timeout_keepalive_sec = -1
  };

  if (ssl) {
    spec.private_key = "./server-eckey.pem";
    spec.private_key_len = -1;
    spec.certs = "./server-ecdsacert.pem";
    spec.certs_len = -1;
  }

  RCC(rc, finish, iwn_http_server_create(&spec, 0));

  iwn_poller_poll(poller);

finish:
  IWN_ASSERT(rc == 0);
  IWN_ASSERT(state & STATE_SERVER_DISPOSED);
  IWN_ASSERT(state & STATE_CLOSED_ON_SIGNAL);
  iwn_poller_destroy(&poller);
  return iwn_assertions_failed > 0 ? 1 : 0;
}

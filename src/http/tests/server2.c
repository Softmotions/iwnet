#include "utils/tests.h"
#include "wf.h"
#include "wf_files.h"

#include <iowow/iwconv.h>

#include <string.h>
#include <signal.h>
#include <errno.h>

#define S_ROOT_DISPOSED 0x01U
static int _handle_get_empty_cnt;
static int _handle_root_cnt;

static uint32_t state;
static struct iwn_poller *poller;
static struct iwn_wf_ctx *ctx;

static void _on_signal(int signo) {
  if (poller) {
    iwn_poller_shutdown_request(poller);
  }
}

static void _on_root_dispose(struct iwn_wf_ctx *ctx, void *data) {
  state |= S_ROOT_DISPOSED;
}

static int _handle_root(struct iwn_wf_req *req, void *user_data) {
  ++_handle_root_cnt;
  if (!iwn_http_response_write(req->http, 404, "text/plain", "Not found from root", -1)) {
    return -1;
  } else {
    return 1;
  }
}

// Get handler in middle of the path
static int _handle_get(struct iwn_wf_req *req, void *user_data) {
  return 0;
}

static int _handle_get_empty(struct iwn_wf_req *req, void *user_data) {
  ++_handle_get_empty_cnt;
  IWN_ASSERT((intptr_t) user_data == 1);
  return 200; // Empty reponse with ok status
}

static int _handle_get_query(struct iwn_wf_req *req, void *user_data) {
  struct iwn_val foo = iwn_pair_find_val(&req->query_params, "foo", -1);
  IWN_ASSERT(foo.len && foo.buf);
  struct iwn_val baz = iwn_pair_find_val(&req->query_params, "baz", -1);
  IWN_ASSERT(baz.len && baz.buf);
  IWN_ASSERT(strcmp(baz.buf, "a@z") == 0);
  IWN_ASSERT(strcmp(foo.buf, "bar") == 0);
  bool ret = iwn_http_response_printf(req->http, 200, "text/plain;", "foo=%s&baz=%s", foo.buf, baz.buf);
  IWN_ASSERT(ret);
  return 1;
}

static int _handle_fail(struct iwn_wf_req *req, void *user_data) {
  return -1;
}

static int _handle_post_urlencoded(struct iwn_wf_req *req, void *user_data) {
  struct iwn_val foo = iwn_pair_find_val(&req->form_params, "foo", -1);
  IWN_ASSERT(foo.len && foo.buf);
  struct iwn_val baz = iwn_pair_find_val(&req->form_params, "baz", -1);
  IWN_ASSERT(baz.len && baz.buf);
  IWN_ASSERT(strcmp(baz.buf, "a@z") == 0);
  IWN_ASSERT(strcmp(foo.buf, "bar") == 0);
  bool ret = iwn_http_response_printf(req->http, 200, "text/plain;", "foo=%s&baz=%s", foo.buf, baz.buf);
  IWN_ASSERT(ret);
  return 1;
}

static int _handle_put_data(struct iwn_wf_req *req, void *user_data) {
  IWN_ASSERT(req->body && req->body_len);
  bool ret = iwn_http_response_write(req->http, 200, "text/plan", req->body, req->body_len);
  IWN_ASSERT(ret);
  return 1;
}

static int _handle_post_bigparam(struct iwn_wf_req *req, void *user_data) {
  struct iwn_val bigparam = iwn_pair_find_val(&req->form_params, "bigparam", -1);
  IWN_ASSERT(bigparam.len && bigparam.buf);
  bool ret = iwn_http_response_write(req->http, 200, "text/plain", bigparam.buf, bigparam.len);
  IWN_ASSERT(ret)
  return 1;
}

static int _handle_post_multipart(struct iwn_wf_req *req, void *user_data) {
  atomic_int af = iwn_assertions_failed;
  struct iwn_pair *p = iwn_pair_find(&req->form_params, "foo", -1);
  IWN_ASSERT(p);
  if (p) {
    IWN_ASSERT(strncmp(p->val, "bar", p->val_len) == 0);
  }
  p = iwn_pair_find(&req->form_params, "baz", -1);
  IWN_ASSERT(p);
  if (p) {  
    IWN_ASSERT(strncmp(p->val, "a%40z", p->val_len) == 0);
  }
  p = iwn_pair_find(&req->form_params, "bigparam", -1);
  IWN_ASSERT(p);
  if (p) {
    IWN_ASSERT(p->val_len == 15165824);
  }
  if (af == iwn_assertions_failed) {
    return 200;
  } else {
    return 500;
  }
}

static int _handle_session_put(struct iwn_wf_req *req, void *user_data) {
  IWN_ASSERT(iwn_wf_session_put(req, "mykey", "70b2a86f-025b-4805-b267-871f3e1bc170") == 0);
  return 200;
}

static int _handle_session_get(struct iwn_wf_req *req, void *user_data) {
  char *val = iwn_wf_session_get(req, "mykey");
  if (val) {
    bool ret = iwn_http_response_write(req->http, 200, "text/plan", val, strlen(val));
    IWN_ASSERT(ret);
    free(val);
    return 1;
  } else {
    return 500;
  }
}

static int _handle_file_get(struct iwn_wf_req *req, void *user_data) {
  const char *path = req->path_unmatched;
  while (*path == '/') ++path;
  return iwn_wf_file_serve(req, 0, path);
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

  // Create WF context

  RCC(rc, finish, iwn_wf_create(&(struct iwn_wf_route) {
    .handler = _handle_root,
    .handler_dispose = _on_root_dispose,
    .tag = "root"
  }, &ctx));

  // Configure routes

  struct iwn_wf_route *r;

  RCC(rc, finish, iwn_wf_route(&(struct iwn_wf_route) {
    .ctx = ctx,
    .pattern = "/get",
    .handler = _handle_get,
  }, &r));

  RCC(rc, finish, iwn_wf_route(&(struct iwn_wf_route) {
    .parent = r,
    .pattern = "/empty",
    .handler = _handle_get_empty,
    .user_data = (void*) 1
  }, 0));

  RCC(rc, finish, iwn_wf_route(&(struct iwn_wf_route) {
    .parent = r,
    .pattern = "/query",
    .handler = _handle_get_query
  }, 0));

  RCC(rc, finish, iwn_wf_route(&(struct iwn_wf_route) {
    .ctx = ctx,
    .pattern = "^/fa.l",
    .handler = _handle_fail,
  }, 0));

  RCC(rc, finish, iwn_wf_route(&(struct iwn_wf_route) {
    .ctx = ctx,
    .pattern = "/post",
    .flags = IWN_WF_POST | IWN_WF_PUT
  }, &r));

  RCC(rc, finish, iwn_wf_route(&(struct iwn_wf_route) {
    .parent = r,
    .pattern = "/urlencoded",
    .handler = _handle_post_urlencoded,
    .flags = IWN_WF_POST
  }, 0));

  RCC(rc, finish, iwn_wf_route(&(struct iwn_wf_route) {
    .parent = r,
    .pattern = "/putdata",
    .handler = _handle_put_data,
    .flags = IWN_WF_PUT
  }, 0));

  RCC(rc, finish, iwn_wf_route(&(struct iwn_wf_route) {
    .parent = r,
    .pattern = "/bigparam",
    .handler = _handle_post_bigparam,
    .flags = IWN_WF_POST
  }, 0));

  RCC(rc, finish, iwn_wf_route(&(struct iwn_wf_route) {
    .parent = r,
    .pattern = "/multipart",
    .handler = _handle_post_multipart,
    .flags = IWN_WF_POST
  }, 0));

  RCC(rc, finish, iwn_wf_route(&(struct iwn_wf_route) {
    .ctx = ctx,
    .pattern = "/session/put",
    .handler = _handle_session_put,
  }, 0));

  RCC(rc, finish, iwn_wf_route(&(struct iwn_wf_route) {
    .ctx = ctx,
    .pattern = "/session/get",
    .handler = _handle_session_get,
  }, 0));

  RCC(rc, finish, iwn_wf_route(&(struct iwn_wf_route) {
    .ctx = ctx,
    .pattern = "/file",
    .handler = _handle_file_get,
    .flags = IWN_WF_MATCH_PREFIX | IWN_WF_GET | IWN_WF_HEAD,
  }, 0));

  // Start the server:
  RCC(rc, finish, iwn_poller_create(nthreads, oneshot, &poller));

  struct iwn_wf_server_spec spec = {
    .listen                        = "localhost",
    .port                          = port,
    .poller                        = poller,
    .request_timeout_sec           = -1,
    .request_timeout_keepalive_sec = -1,
  };

  if (ssl) {
    spec.ssl.private_key = "./server-eckey.pem";
    spec.ssl.private_key_len = -1;
    spec.ssl.certs = "./server-ecdsacert.pem";
    spec.ssl.certs_len = -1;
  }

  RCC(rc, finish, iwn_wf_server(&spec, ctx));

  iwn_poller_poll(poller);

finish:
  IWN_ASSERT(rc == 0);
  //IWN_ASSERT(_handle_get_empty_cnt == 1);
  //IWN_ASSERT(_handle_root_cnt == 1);
  IWN_ASSERT(state & S_ROOT_DISPOSED);
  iwn_poller_destroy(&poller);
  return iwn_assertions_failed > 0 ? 1 : 0;
}

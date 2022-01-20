#include "utils/tests.h"
#include "wf.h"

#include <iowow/iwconv.h>

#include <string.h>
#include <signal.h>
#include <errno.h>

#define S_ROOT_DISPOSED 0x01U

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
  return 0;
}

static int _handle_get_empty(struct iwn_wf_req *req, void *user_data) {
  return 200; // Empty reponse with ok status
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

  RCC(rc, finish, iwn_wf_route_create(&(struct iwn_wf_route) {
    .ctx = ctx,
    .pattern = "/get"
  }, &r));

  RCC(rc, finish, iwn_wf_route_create(&(struct iwn_wf_route) {
    .parent = r,
    .pattern = "/empty",
    .user_data = (void*) 1
  }, 0));

  // Start the server

  RCC(rc, finish, iwn_poller_create(nthreads, oneshot, &poller));

  struct iwn_wf_server_spec spec = {
    .listen                        = "localhost",
    .port                          = port,
    .poller                        = poller,
    .request_timeout_sec           = -1,
    .request_timeout_keepalive_sec = -1,
  };

  if (ssl) {
    spec.private_key = "./server-eckey.pem";
    spec.private_key_len = -1;
    spec.certs = "./server-ecdsacert.pem";
    spec.certs_len = -1;
  }

  RCC(rc, finish, iwn_wf_server_create(&spec, ctx));

  iwn_poller_poll(poller);

finish:
  IWN_ASSERT(rc == 0);
  iwn_poller_destroy(&poller);
  return iwn_assertions_failed > 0 ? 1 : 0;
}

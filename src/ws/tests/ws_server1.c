#include "utils/tests.h"
#include "ws_server.h"

#include <iowow/iwconv.h>

#include <string.h>
#include <signal.h>
#include <errno.h>

static struct iwn_poller *poller;
static struct iwn_wf_ctx *ctx;

static void _on_signal(int signo) {
  if (poller) {
    iwn_poller_shutdown_request(poller);
  }
}

static int _handle_root(struct iwn_wf_req *req, void *user_data) {
  return 0;
}

static bool _on_ws_echo(struct iwn_ws_sess *sess, const char *msg, size_t msg_len) {
  IWN_ASSERT_FATAL(sess && msg && msg_len);
  IWN_ASSERT(sess->spec->user_data == ctx);
  fprintf(stderr, "Got message %s\n", msg);
  return true;
}

static void _on_ws_session_init(struct iwn_ws_sess *sess) {
  IWN_ASSERT_FATAL(sess);
  IWN_ASSERT(sess->spec->user_data == ctx);
  fprintf(stderr, "Session init\n");
}

static void _on_ws_session_dispose(struct iwn_ws_sess *sess) {
  IWN_ASSERT_FATAL(sess);
  IWN_ASSERT(sess->spec->user_data == ctx);
  fprintf(stderr, "Session dispose\n");
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
    .handler = _handle_root
  }, &ctx));

  RCC(rc, finish, iwn_wf_route(iwn_ws_server_route_attach(&(struct iwn_wf_route) {
    .ctx = ctx,
    .pattern = "/ws"
  }, &(struct iwn_ws_handler_spec) {
    .handler = _on_ws_echo,
    .user_data = ctx,
    .on_session_init = _on_ws_session_init,
    .on_session_dispose = _on_ws_session_dispose,
  }), 0));
  
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
    spec.private_key = "./key.pem";
    spec.private_key_len = -1;
    spec.certs = "./cert.pem";
    spec.certs_len = -1;
  }

  RCC(rc, finish, iwn_wf_server(&spec, ctx));

  iwn_poller_poll(poller);

finish:
  IWN_ASSERT(rc == 0);
  return iwn_assertions_failed > 0 ?: 0;
}

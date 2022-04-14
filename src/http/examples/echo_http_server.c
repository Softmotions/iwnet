/// Sample echo HTTP server.
///
/// Run server:
///   ./echo_http_server --ssl
///
/// Client:
///  curl -XPUT -d'Hello' http://localhost:8080/echo

#include "iwn_wf.h"

#include <iowow/iwconv.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <errno.h>

static struct iwn_poller *poller;
static struct iwn_wf_ctx *ctx;

static void _on_signal(int signo) {
  fprintf(stderr, "\nExiting...\n");
  iwn_poller_shutdown_request(poller);
}

static int _handle_echo(struct iwn_wf_req *req, void *user_data) {
  fprintf(stderr, "Echo handler called\n");
  iwn_http_response_printf(req->http, 200, "text/plain", "%.*s\n%s\n",
                           (int) req->body_len, req->body, (char*) user_data);
  return IWN_WF_RES_PROCESSED;
}

int main(int argc, char *argv[]) {
  signal(SIGPIPE, SIG_IGN);
  if (  signal(SIGTERM, _on_signal) == SIG_ERR
     || signal(SIGINT, _on_signal) == SIG_ERR) {
    return EXIT_FAILURE;
  }

  iwrc rc = 0;
  bool ssl = false;
  int port = 8080;

  for (int i = 1; i < argc; ++i) {
    if (strcmp(argv[i], "--ssl") == 0) {
      ssl = true;
    } else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
      port = iwatoi(argv[i + 1]);
    }
  }
  RCC(rc, finish, iw_init());              // Init iowow runtime, logging, etc..
  RCC(rc, finish, iwn_wf_create(0, &ctx)); // Create web server context
  RCC(rc, finish, iwn_wf_route(&(struct iwn_wf_route) {
    .ctx = ctx,
    .pattern = "/echo",
    .handler = _handle_echo,
    .user_data = "I'm an echo web server",
    .flags = IWN_WF_PUT | IWN_WF_POST
  }, 0));

  RCC(rc, finish, iwn_poller_create(0, 0, &poller));

  struct iwn_wf_server_spec spec = {
    .listen = "localhost",
    .port   = port,
    .poller = poller,
  };
  if (ssl) {
    spec.ssl.private_key = "./server-eckey.pem";
    spec.ssl.private_key_len = -1;
    spec.ssl.certs = "./server-ecdsacert.pem";
    spec.ssl.certs_len = -1;
  }

  // Print out a routes configuration.
  iwn_wf_route_print(ctx->root, stderr);
  // Configure HTTP server.
  RCC(rc, finish, iwn_wf_server(&spec, ctx));
  fprintf(stderr,
          "\nOpen terminal and run:\n\tcurl -k -XPUT -d'Hello' %s://%s:%d/echo\n",
          (ssl ? "https" : "http"),
          spec.listen,
          spec.port);

  // Start fds poller reactor.
  iwn_poller_poll(poller);

finish:
  iwn_poller_destroy(&poller);
  if (rc) {
    iwlog_ecode_error3(rc);
    return EXIT_FAILURE;
  } else {
    return EXIT_SUCCESS;
  }
}

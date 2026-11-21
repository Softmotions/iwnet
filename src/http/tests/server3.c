/*
 * HTTP server which switches between the plain text and the TLS modes at runtime.
 *
 * The server starts in the plain text mode and applies commands read from stdin:
 * `secure` enables TLS, `plain` disables it and `quit` stops the server. Each
 * switch replaces the TLS settings shared by the server connections, so
 * `server3-tests-run.sh` issues HTTP requests between the commands and checks
 * that the server serves both plain text and TLS requests across all switches.
 */

#include "iwn_http_server.h"
#include "iwn_tests_tls.h"

#include <iowow/iwlog.h>
#include <iowow/iwconv.h>

#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static struct iwn_poller *poller;
static int server_fd = -1;

static const struct iwn_http_server_ssl_spec *secure_spec;

static void _on_signal(int signo) {
  if (poller) {
    iwn_poller_shutdown_request(poller);
  }
}

static bool _request_handler(struct iwn_http_req *req) {
  iwn_http_response_header_set(req, "content-type", "text/plain", -1);
  iwn_http_response_body_set(req, "server3", -1, 0);
  iwn_http_response_end(req);
  return true;
}

/// Applies `secure` / `plain` / `quit` commands, all others are ignored.
static void* _control_thread(void *d) {
  static const struct iwn_http_server_ssl_spec plain_spec = { 0 };
  char cmd[64];

  while (fgets(cmd, sizeof(cmd), stdin)) {
    cmd[strcspn(cmd, "\r\n")] = '\0';
    if (strcmp(cmd, "secure") == 0) {
      bool ok = iwn_http_server_ssl_set(poller, server_fd, secure_spec);
      fprintf(stderr, "server3: secure: %s\n", ok ? "ok" : "failed");
    } else if (strcmp(cmd, "plain") == 0) {
      bool ok = iwn_http_server_ssl_set(poller, server_fd, &plain_spec);
      fprintf(stderr, "server3: plain: %s\n", ok ? "ok" : "failed");
    } else if (strcmp(cmd, "quit") == 0) {
      iwn_poller_shutdown_request(poller);
      break;
    }
  }
  return 0;
}

int main(int argc, char *argv[]) {
  iwrc rc = 0;
  int port = 9393;

  iwlog_init();
  signal(SIGPIPE, SIG_IGN);
  signal(SIGHUP, SIG_IGN);
  if (signal(SIGTERM, _on_signal) == SIG_ERR || signal(SIGINT, _on_signal) == SIG_ERR) {
    return EXIT_FAILURE;
  }

  for (int i = 0; i < argc; ++i) {
    if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
      port = iwatoi(argv[i + 1]);
    }
  }

  RCC(rc, finish, iwn_poller_create(1, 1, &poller));
  RCC(rc, finish, iwn_http_server_create(&(struct iwn_http_server_spec) {
    .listen = "localhost",
    .port = port,
    .poller = poller,
    .request_handler = _request_handler,
    .request_timeout_sec = -1,
    .request_timeout_keepalive_sec = -1,
  }, &server_fd));

  const struct iwn_http_server_ssl_spec secure = {
    .tls_impl = iwn_test_tls_impl(),
    .certs = "./server-ecdsacert.pem",
    .certs_len = -1,
    .private_key = "./server-eckey.pem",
    .private_key_len = -1,
  };
  secure_spec = &secure;

  pthread_t control_thread;
  RCN(finish, pthread_create(&control_thread, 0, _control_thread, 0));

  fprintf(stderr, "server3: ready\n");
  iwn_poller_poll(poller);
  pthread_join(control_thread, 0);

finish:
  if (rc) {
    iwlog_ecode_error3(rc);
  }
  iwn_poller_destroy(&poller);
  return rc ? EXIT_FAILURE : EXIT_SUCCESS;
}

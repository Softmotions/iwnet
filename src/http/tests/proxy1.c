#include "iwn_tests.h"
#include "iwn_wf.h"
#include "iwn_proc.h"

#include <signal.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

static struct iwn_poller *poller;
static struct iwn_wf_ctx *ctx;
static int endpoint_pid = -1;

static void _on_signal(int signo) {
  if (endpoint_pid > -1) {
    kill(endpoint_pid, SIGTERM);
  }
  if (poller) {
    iwn_poller_shutdown_request(poller);
  }
}

static void _on_endpoint_server_output(const struct iwn_proc_ctx *ctx, const char *buf, size_t len) {
  fprintf(stderr, "[Endpoint]: %.*s", (int) len, buf);
}

static void _on_endpoint_server_exit(const struct iwn_proc_ctx *ctx) {
  endpoint_pid = -1;
  fprintf(stderr, "Endpoint server exit\n");
  iwn_poller_shutdown_request(poller);
}

static int _handle_root(struct iwn_wf_req *req, void *user_data) {
  if (!iwn_http_response_write(req->http, 404, "text/plain", "Not found from root", -1)) {
    return -1;
  } else {
    return IWN_WF_RES_PROCESSED;
  }
}

static iwrc _endpoint_spawn(void) {
  return iwn_proc_spawn(&(struct iwn_proc_spec) {
    .poller = poller,
    .path = "./server2",
    .args = (const char*[]) { "--port", "9393", 0 },
    .on_stdout = _on_endpoint_server_output,
    .on_stderr = _on_endpoint_server_output,
    .on_exit = _on_endpoint_server_exit,
  }, &endpoint_pid);
}

static void _on_request_dispose(struct iwn_http_req *req) {
}

static bool _server_proxy_handler(struct iwn_http_req *req) {
  struct iwn_val val = iwn_http_request_header_get(req, "host", IW_LLEN("host"));
  if ((val.len == IW_LLEN("endpoint") && strncmp(val.buf, "endpoint", val.len) == 0)) {
    req->on_request_dispose = _on_request_dispose;
    iwn_http_proxy_header_set(req, "Forwarded", "0.0.0.0", IW_LLEN("0.0.0.0"));
    return iwn_http_proxy_url_set(req, "http://localhost:9393", -1);
  }
  return false;
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

  int port = 9292;
  struct iwn_wf_route *r;

  RCC(rc, finish, iwn_poller_create(4, 1, &poller));

  RCC(rc, finish, iwn_wf_create(&(struct iwn_wf_route) {
    .handler = _handle_root,
    .tag = "root"
  }, &ctx));

  struct iwn_wf_server_spec spec = {
    .listen = "localhost",
    .port = port,
    .poller = poller,
    .proxy_handler = _server_proxy_handler,
    .request_timeout_sec = -1,
    .request_timeout_keepalive_sec = -1,
  };

  RCC(rc, finish, iwn_wf_server(&spec, ctx));
  RCC(rc, finish, _endpoint_spawn());
  sleep(1);

  iwn_poller_poll(poller);
  iwn_proc_dispose2(SIGTERM, 10000);

finish:
  IWN_ASSERT(rc == 0);
  iwn_poller_destroy(&poller);
  return iwn_assertions_failed > 0 ? 1 : 0;
}

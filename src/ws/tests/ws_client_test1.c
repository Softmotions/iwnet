
#include "iwn_tests.h"
#include "iwn_proc.h"
#include "iwn_ws_client.h"

#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <signal.h>

static struct iwn_poller *poller;
static struct iwn_ws_client *ws;
static int cnt;
static int ws_server_pid;
static char *listen = "localhost";

static void on_connected(const struct iwn_ws_client_ctx *ctx) {
  IWN_ASSERT(iwn_ws_client_write_text(ctx->ws, "Test", sizeof("Test") - 1));
}

static void on_message(const struct iwn_ws_client_ctx *ctx, const char *buf, size_t buf_len, uint8_t frame) {
  fprintf(stderr, "on_message %.*s\n", (int) buf_len, buf);
  if (cnt++ < 3) {
    IWN_ASSERT(iwn_ws_client_write_text(ctx->ws, "Test", sizeof("Test") - 1));
  } else {
    iwn_ws_client_close(ctx->ws);
  }
}

static void _on_ws_server_exit(const struct iwn_proc_ctx *ctx) {
  fprintf(stderr, "On ws server exit\n");
  iwn_poller_shutdown_request(poller);
}

static void on_dispose(const struct iwn_ws_client_ctx *ctx) {
  fprintf(stderr, "Killing ws server: %d\n", ws_server_pid);
  iwn_proc_kill(ws_server_pid, SIGINT);
  IWN_ASSERT(iwn_ws_client_destroy(ctx->ws));
  ws = 0;
}

static void _on_ws_server_output(const struct iwn_proc_ctx *ctx, const char *buf, size_t len) {
  fprintf(stderr, "ws server: %s\n", buf);

  if (!strstr(buf, "0542a108-ff0f-47ef-86e3-495fd898a8ee")) {
    return;
  }

  const char *url = "ws://localhost:9292/ws";
  if (strstr(listen, "socket://") == listen) {
    url = listen;
  }

  iwrc rc = iwn_ws_client_open(&(struct iwn_ws_client_spec) {
    .url = url,
    .path_ext = "/ws",
    .poller = poller,
    .on_connected = on_connected,
    .on_message = on_message,
    .on_dispose = on_dispose,
  }, &ws);

  IWN_ASSERT(rc == 0);
  IWN_ASSERT(ws);
  if (rc) {
    iwn_proc_kill(ws_server_pid, SIGINT);
  }
}

int main(int argc, char *argv[]) {
  iwrc rc = 0;
  iwlog_init();

  for (int i = 0; i < argc; ++i) {
    if (strcmp(argv[i], "--listen") == 0 && i + 1 < argc) {
      listen = argv[i + 1];
    }
  }

  RCC(rc, finish, iwn_poller_create(1, 1, &poller));
  RCC(rc, finish, iwn_proc_spawn(&(struct iwn_proc_spec) {
    .poller = poller,
    .path = "./ws_server1",
    .args = (const char*[]) { "--listen", listen, 0 },
    .on_stdout = _on_ws_server_output,
    .on_stderr = _on_ws_server_output,
    .on_exit = _on_ws_server_exit,
#ifdef __linux__
    .parent_death_signal = SIGTERM,
#endif
  }, &ws_server_pid));
 
  iwn_poller_poll(poller);
  iwn_proc_dispose2(SIGTERM, 0);
  iwn_poller_destroy(&poller);

finish:
  IWN_ASSERT(rc == 0);
  IWN_ASSERT(ws == 0);
  IWN_ASSERT(cnt == 4);
  return iwn_assertions_failed > 0 ? 1 : 0;
}

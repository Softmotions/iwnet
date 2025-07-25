#include "iwn_tests.h"
#include "iwn_proc.h"
#include "iwn_ws_client.h"

#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <signal.h>

static struct iwn_poller *poller;
static struct iwn_ws_client *ws;
static int ws_server_pid;

static int ccnt;

static void on_connected(const struct iwn_ws_client_ctx *ctx) {
  ++ccnt;
  IWN_ASSERT(iwn_ws_client_write_text(ctx->ws, "Init", IW_LLEN("Init")));
}

static void on_message(const struct iwn_ws_client_ctx *ctx, const char *buf, size_t buf_len, uint8_t frame) {
  fprintf(stderr, "on_message %.*s\n", (int) buf_len, buf);
  if (ccnt > 2) {
    fprintf(stderr, "closing client\n");
    iwn_ws_client_close(ctx->ws);
  } else {
    // Request disconnect
    IWN_ASSERT(iwn_ws_client_write_text(ctx->ws, "disconnect", IW_LLEN("disconnect")));
  }
}

static void on_dispose(const struct iwn_ws_client_ctx *ctx) {
  fprintf(stderr, "Killing ws server: %d\n", ws_server_pid);
  iwn_proc_kill(ws_server_pid, SIGINT);
}

static void _on_ws_server_output(const struct iwn_proc_ctx *ctx, const char *buf, size_t len) {
  fprintf(stderr, "ws server: %s\n", buf);
  if (!strstr(buf, "0542a108-ff0f-47ef-86e3-495fd898a8ee")) {
    return;
  }
  iwrc rc = iwn_ws_client_open(&(struct iwn_ws_client_spec) {
    .url = "ws://localhost:9292/ws",
    .poller = poller,
    .on_connected = on_connected,
    .on_message = on_message,
    .on_dispose = on_dispose,
    .reconnect_attempt_pause_sec = 1,
    .reconnect_attempts_num = 1
  }, &ws);
  IWN_ASSERT(rc == 0);
  IWN_ASSERT(ws);
  if (rc) {
    iwn_proc_kill(ws_server_pid, SIGINT);
  }
}

static void _on_ws_server_exit(const struct iwn_proc_ctx *ctx) {
  fprintf(stderr, "On ws server exit\n");
  iwn_poller_shutdown_request(poller);
}

int main(int argc, char *argv[]) {
  iwrc rc = 0;
  iwlog_init();

  RCC(rc, finish, iwn_poller_create(1, 1, &poller));
  RCC(rc, finish, iwn_proc_spawn(&(struct iwn_proc_spec) {
    .poller = poller,
    .path = "./ws_server1",
    .args = (const char*[]) { 0 },
    .on_stdout = _on_ws_server_output,
    .on_stderr = _on_ws_server_output,
    .on_exit = _on_ws_server_exit
  }, &ws_server_pid));

  iwn_poller_poll(poller);

  iwn_proc_dispose2(SIGTERM, 10000);
  iwn_poller_destroy(&poller);
  IWN_ASSERT(iwn_ws_client_destroy(ws));

finish:
  IWN_ASSERT(rc == 0);
  IWN_ASSERT(ccnt == 3);
  return iwn_assertions_failed > 0 ? 1 : 0;
}

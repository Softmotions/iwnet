
#include "utils/tests.h"
#include "proc.h"
#include "ws/ws.h"

#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <signal.h>
#include <wait.h>

static struct poller *poller;
static struct ws *ws;
static int cnt;
static int ws_server_pid;

static void on_connected(const struct ws_ctx *ctx) {
  iwrc rc = ws_write_text(ctx->ws, "Test", sizeof("Test") - 1);
  IWN_ASSERT(rc == 0);
  if (rc) {
    iwlog_ecode_error3(rc);
  }
}

static void on_message(const char *buf, size_t buf_len, const struct ws_ctx *ctx) {
  iwrc rc = 0;
  fprintf(stderr, "on_message %.*s\n", (int) buf_len, buf);
  if (cnt++ < 3) {
    rc = ws_write_text(ctx->ws, "Test", sizeof("Test") - 1);
  } else {
    ws_close(ctx->ws);
  }
  IWN_ASSERT(rc == 0);
  if (rc) {
    iwlog_ecode_error3(rc);
  }
}

static void _on_ws_server_exit(const struct proc_ctx *ctx) {
  fprintf(stderr, "On ws server exit\n");
  poller_shutdown_request(poller);
}

static void on_dispose(const struct ws_ctx *ctx) {
  ws = 0;
  fprintf(stderr, "on_dispose Killing ws server: %d\n", ws_server_pid);
  proc_kill(ws_server_pid, SIGINT);
  proc_wait(ws_server_pid);
}

static void _on_ws_server_output(const struct proc_ctx *ctx, const char *buf, size_t len) {
  fprintf(stderr, "ws server: %s\n", buf);
  if (!strstr(buf, "0542a108-ff0f-47ef-86e3-495fd898a8ee")) {
    return;
  }
  iwrc rc = ws_open(&(struct ws_spec) {
    .url = "wss://localhost:7772",
    .poller = poller,
    .on_connected = on_connected,
    .on_message = on_message,
    .on_dispose = on_dispose,
    .verify_peer = false,
    .verify_host = false
  }, &ws);
  IWN_ASSERT(rc == 0);
  if (rc) {
    iwlog_ecode_error3(rc);
    proc_kill(ws_server_pid, SIGINT);
  }
}

int main(int argc, char *argv[]) {
  iwrc rc = 0;
  iwlog_init();

  RCC(rc, finish, poller_create(1, 1, &poller));
  RCC(rc, finish, proc_spawn(&(struct proc_spec) {
    .poller = poller,
    .path = "/usr/bin/node",
    .args = (const char*[]) { "wss.js", "7772", 0 },
    .on_stdout = _on_ws_server_output,
    .on_stderr = _on_ws_server_output,
    .on_exit = _on_ws_server_exit
  }, &ws_server_pid));

  poller_poll(poller);
  proc_dispose();
  poller_destroy(&poller);

finish:
  IWN_ASSERT(rc == 0);
  IWN_ASSERT(ws == 0);
  IWN_ASSERT(cnt == 4);
  return asserts_failed > 0 ? 1 : 0;
}


#include "utils/tests.h"
#include "ws/ws.h"

#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <signal.h>
#include <wait.h>

static struct poller *poller;
static struct ws *ws;
static int cnt;

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

static void on_dispose(const struct ws_ctx *ctx) {
  ws = 0;
  poller_shutdown_request(poller);
}

int main(int argc, char *argv[]) {
  iwrc rc = 0;
  iwlog_init();

  RCC(rc, finish, poller_create(1, 1, &poller));
  RCC(rc, finish, ws_open(&(struct ws_spec) {
    .url = "wss://echo.websocket.org",
    .poller = poller,
    .on_connected = on_connected,
    .on_message = on_message,
    .on_dispose = on_dispose,
    .verify_peer = true,
    .verify_host = true
  }, &ws));

  poller_poll(poller);
  poller_destroy(&poller);

finish:
  IWN_ASSERT(rc == 0);
  IWN_ASSERT(ws == 0);
  IWN_ASSERT(cnt == 4);
  return asserts_failed > 0 ? 1 : 0;
}

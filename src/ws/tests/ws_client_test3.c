
#include "utils/tests.h"
#include "ws/ws.h"

#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <signal.h>
#include <wait.h>

static struct iwn_poller *poller;
static struct iwn_ws *ws;
static int cnt;

static void on_connected(const struct iwn_ws_ctx *ctx) {
  iwrc rc = iwn_ws_write_text(ctx->ws, "Test", sizeof("Test") - 1);
  IWN_ASSERT(rc == 0);
  if (rc) {
    iwlog_ecode_error3(rc);
  }
}

static void on_message(const char *buf, size_t buf_len, const struct iwn_ws_ctx *ctx) {
  iwrc rc = 0;
  fprintf(stderr, "on_message %.*s\n", (int) buf_len, buf);
  if (cnt++ < 3) {
    rc = iwn_ws_write_text(ctx->ws, "Test", sizeof("Test") - 1);
  } else {
    iwn_ws_close(ctx->ws);
  }
  IWN_ASSERT(rc == 0);
  if (rc) {
    iwlog_ecode_error3(rc);
  }
}

static void on_dispose(const struct iwn_ws_ctx *ctx) {
  ws = 0;
  iwn_poller_shutdown_request(poller);
}

int main(int argc, char *argv[]) {
  iwrc rc = 0;
  iwlog_init();

  RCC(rc, finish, iwn_poller_create(1, 1, &poller));
  RCC(rc, finish, iwn_ws_open(&(struct iwn_ws_spec) {
    .url = "wss://echo.websocket.org",
    .poller = poller,
    .on_connected = on_connected,
    .on_message = on_message,
    .on_dispose = on_dispose,
    .verify_peer = true,
    .verify_host = true
  }, &ws));

  iwn_poller_poll(poller);
  iwn_poller_destroy(&poller);

finish:
  IWN_ASSERT(rc == 0);
  IWN_ASSERT(ws == 0);
  IWN_ASSERT(cnt == 4);
  return iwn_asserts_failed > 0 ? 1 : 0;
}

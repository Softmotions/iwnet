#include "iwn_tests.h"
#include "iwn_grpc_client.h"
#include "iwn_poller.h"

#include <iowow/iwarr.h>
#include <iowow/iwconv.h>
#include <iowow/iwpool.h>
#include <getopt.h>
#include <string.h>


#define STATE_ON_HANDSHAKE 0x01U
#define STATE_ON_ERROR     0x02U
#define STATE_ON_CLOSED    0x04U
#define STATE_ON_DESTROY   0x08U

static struct _ctx {
  struct iwn_grpc_client *client;
  struct iwn_poller *poller;
  struct iwpool     *pool;
  char *connect_url;
  struct iwulist messages; /// struct iwn_val
  uint32_t       state;
  iwrc rc;
  const char *error_explained;
} ctx;

static void _on_signal(int signo) {
  if (ctx.poller) {
    iwn_poller_shutdown_request(ctx.poller);
  }
}

static void _ctx_destroy(void) {
  iwn_grpc_client_close(ctx.client);
  iwn_poller_destroy(&ctx.poller);
  iwulist_destroy_keep(&ctx.messages);
  iwpool_destroy(ctx.pool);
}

static iwrc _on_handshake(struct iwn_grpc_client_ctx *cc) {
  ctx.state |= STATE_ON_HANDSHAKE;
  return 0;
}

static void _on_closed(struct iwn_grpc_client_ctx *cc) {
  ctx.state |= STATE_ON_CLOSED;
}

static void _on_error(struct iwn_grpc_client_ctx *cc) {
  ctx.state |= STATE_ON_ERROR;
}

static void _on_destroy(struct iwn_grpc_client_ctx *cc) {
  ctx.state |= STATE_ON_DESTROY;
}

int main(int argc, char *argv[]) {
  ssize_t len;

  iwrc rc = iwn_grpc_init();
  RCRET(rc);

  struct iwpool *pool = iwpool_create_empty();
  RCB(finish, pool);

  ctx.pool = pool;
  iwulist_init(&ctx.messages, 3, sizeof(struct iwn_val));

  static const struct option long_options[] = {
    "message", 1, 0, 'm',
    "connect", 1, 0, 'c',
    0
  };

  for (int ch; (ch = getopt_long(argc, argv, "m:c:", long_options, 0)) != -1; ) {
    switch (ch) {
      case 'm': {
        struct iwn_val v = { 0 };
        len = v.len = strlen(optarg);
        if (v.len & 0x01) {
          v.len++;
        }
        v.len /= 2;
        IWN_ASSERT_FATAL(v.len > 0);
        RCB(finish, v.buf = iwpool_calloc(v.len, pool));
        v.len = iwhex2bin(optarg, len, v.buf, len);
        RCC(rc, finish, iwulist_push(&ctx.messages, &v));
      }
      break;
      case 'c':
        RCB(finish, ctx.connect_url = iwpool_strdup2(pool, optarg));
        break;
      default:
        fprintf(stderr, "Invalid option provided\n");
        rc = IW_ERROR_INVALID_ARGS;
        goto finish;
    }
  }
  struct iwn_grpc_client_spec spec = {
    .url = "grpc+plaintext://localhost:50051",
    .poller = ctx.poller,
    .on_handshake = _on_handshake,
    .on_closed = _on_closed,
    .on_error = _on_error,
    .on_destroy = _on_destroy,
  };

  RCC(rc, finish, iwn_poller_create(3, 1, &ctx.poller));
  RCC(rc, finish, iwn_grpc_client_open(&spec, &ctx.client));

  iwn_poller_poll(ctx.poller);


finish:
  if (rc) {
    iwlog_ecode_error3(rc);
  }
  IWN_ASSERT(rc == 0);
  _ctx_destroy();
  return iwn_assertions_failed > 0 ? 1 : 0;
}

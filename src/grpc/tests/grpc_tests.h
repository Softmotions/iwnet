#include "iwn_tests.h"
#include "iwn_grpc_client.h"
#include "iwn_poller.h"
#include "iwstepbox.h"

#include <iowow/iwarr.h>
#include <iowow/iwconv.h>
#include <iowow/iwpool.h>
#include <getopt.h>
#include <string.h>
#include <pthread.h>
#include <signal.h>
#include <unistd.h>

static struct iw_stepbox sbox[16];

#define STEP_ON_HANDSHAKE   (uint8_t) 1
#define STEP_REQ_ON_DRAINED (uint8_t) 2
#define STEP_REQ_ON_MESSAGE (uint8_t) 3
#define STEP_REQ_ON_ERROR   (uint8_t) 4
#define STEP_REQ_ON_CLOSED  (uint8_t) 5
#define STEP_REQ_ON_DESTROY (uint8_t) 6
#define STEP_ON_CLOSED      (uint8_t) 7
#define STEP_ON_DESTROY     (uint8_t) 8
#define STEP_ON_ERROR       (uint8_t) 9

static const char* _step_name(uint8_t s) {
  switch (s) {
    case STEP_ON_HANDSHAKE:
      return "on_handshake";
    case STEP_REQ_ON_DRAINED:
      return "req_on_drained";
    case STEP_REQ_ON_MESSAGE:
      return "req_on_message";
    case STEP_REQ_ON_ERROR:
      return "req_on_error";
    case STEP_REQ_ON_CLOSED:
      return "req_on_closed";
    case STEP_REQ_ON_DESTROY:
      return "req_on_destroy";
    case STEP_ON_CLOSED:
      return "on_closed";
    case STEP_ON_DESTROY:
      return "on_destroy";
    case STEP_ON_ERROR:
      return "on_error";
    default:
      return "unknown";
  }
}

static void _sbox_lsnr(struct iw_stepbox *sb, uint8_t idx, int inc) {
  fprintf(stderr, "Step: %s %d\n", _step_name(idx), sb->steps[idx]);
  return;
}

static struct _ctx {
  struct iwn_grpc_client *client;
  struct iwn_poller      *poller;
  struct iwpool *pool;
  char *connect_url;
  iwrc  rc;
  const char *error_explained;
} _ctx;

static void _on_signal(int signo) {
  fprintf(stderr, "On signal: %d\n", signo);
  if (_ctx.poller) {
    iwn_poller_shutdown_request(_ctx.poller);
  }
}

static void _ctx_destroy(void) {
  iwn_grpc_client_close(_ctx.client);
  iwn_poller_destroy(&_ctx.poller);
  iwpool_destroy(_ctx.pool);
}

static iwrc _on_handshake(struct iwn_grpc_client_ctx *cc) {
  iw_stepbox_on(&sbox[0], STEP_ON_HANDSHAKE, 1);
  return 0;
}

static void _on_closed(struct iwn_grpc_client_ctx *cc) {
  iw_stepbox_on(&sbox[0], STEP_ON_CLOSED, 1);
}

static void _on_error(struct iwn_grpc_client_ctx *cc) {
  iw_stepbox_on(&sbox[0], STEP_ON_ERROR, 1);
  IWN_ASSERT(cc->rc);
  if (cc->rc) {
    iwlog_ecode_error2(cc->rc, "on_error");
  }
}

static void _on_destroy(struct iwn_grpc_client_ctx *cc) {
  IWN_ASSERT(_ctx.client == cc->client);
  _ctx.client = 0;
  iw_stepbox_on(&sbox[0], STEP_ON_DESTROY, 1);
}

static void _iwn_val_init(struct iwn_val *val, const char *hex) {
  memset(val, 0, sizeof(*val));
  size_t hexlen = strlen(hex);
  size_t nbytes = hexlen / 2;
  IWN_ASSERT_FATAL(nbytes * 2 == hexlen);
  char *buf = malloc(nbytes);
  IWN_ASSERT_FATAL(buf);
  val->len = iwhex2bin(hex, hexlen, buf, nbytes);
  val->buf = buf;
};

static void _iwn_val_destroy(struct iwn_val *val) {
  iwn_val_buf_free(val);
}

struct _req_test_ctx {
  iwrc rc;
  struct iwpool  *pool;
  const char     *error;
  struct iwn_vals vals;
  uint32_t req_id;
  bool     stop_streaming;
};

static void _req_on_destroy_impl(const struct _req_test_ctx *tctx) {
  IWN_ASSERT(tctx);
  if (tctx) {
    if (tctx->rc) {
      iwlog_ecode_error2(tctx->rc, "_req_test_ctx error");
    }
    iwpool_destroy(tctx->pool);
  }
}

static void _req_on_destroy(const struct iwn_grpc_req_ctx *rctx) {
  struct _req_test_ctx *tctx = rctx->spec.user_data;
  _req_on_destroy_impl(tctx);
}

static void _req_on_closed(const struct iwn_grpc_req_ctx *rctx) {
  struct _req_test_ctx *tctx = rctx->spec.user_data;
  iw_stepbox_on(&sbox[0], STEP_REQ_ON_CLOSED, 1);
  // Request closed now terminate grpc client session
  bool ret = iwn_grpc_client_close(rctx->client_ctx.client);
  IWN_ASSERT(ret);
}

static void _req_on_error(const struct iwn_grpc_req_ctx *ctx) {
  iw_stepbox_on(&sbox[0], STEP_REQ_ON_ERROR, 1);
  struct _req_test_ctx *tctx = ctx->spec.user_data;
  IWN_ASSERT(!tctx->rc);
  IWN_ASSERT(!tctx->error);
  IWN_ASSERT(ctx->rc);
  tctx->rc = ctx->rc;
  if (ctx->error_explained) {
    tctx->error = iwpool_strdup2(tctx->pool, ctx->error_explained);
  }
  iwlog_ecode_error(ctx->rc, "_req_on_error: %s", (ctx->error_explained ? ctx->error_explained : ""));
}

static void _req_on_outgoing_messages_queue_drained(struct iwn_grpc_req_ctx *rctx) {
  iw_stepbox_on(&sbox[0], STEP_REQ_ON_DRAINED, 1);
}

struct _req_test_ctx* _req_test_ctx_create(void) {
  iwrc rc = 0;
  struct iwpool *pool = iwpool_create_empty();
  RCB(finish, pool);
  struct _req_test_ctx *rctx = iwpool_calloc(sizeof(*rctx), pool);
  RCB(finish, rctx);
  rctx->pool = pool;
finish:
  IWN_ASSERT(rc == 0);
  if (rc) {
    return 0;
  } else {
    return rctx;
  }
}

static void _signals_setup(void) {
  signal(SIGPIPE, SIG_IGN);
  signal(SIGHUP, SIG_IGN);
  signal(SIGALRM, SIG_IGN);
  signal(SIGUSR1, SIG_IGN);
  signal(SIGUSR2, SIG_IGN);
  if (signal(SIGTERM, _on_signal) == SIG_ERR) {
    _exit(EXIT_FAILURE);
  }
  if (signal(SIGINT, _on_signal) == SIG_ERR) {
    _exit(EXIT_FAILURE);
  }
}

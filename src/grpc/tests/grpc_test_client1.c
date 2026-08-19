#include "iwn_tests.h"
#include "iwn_grpc_client.h"
#include "iwn_poller.h"

#include <iowow/iwarr.h>
#include <iowow/iwconv.h>
#include <iowow/iwpool.h>
#include <getopt.h>
#include <string.h>
#include <pthread.h>


#define STATE_ON_HANDSHAKE 0x01U
#define STATE_ON_ERROR     0x02U
#define STATE_ON_CLOSED    0x04U
#define STATE_ON_DESTROY   0x08U

static struct _ctx {
  struct iwn_grpc_client *client;
  struct iwn_poller      *poller;
  struct iwpool *pool;
  char    *connect_url;
  uint32_t state;
  iwrc     rc;
  const char *error_explained;
} _ctx;

static void _on_signal(int signo) {
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
  _ctx.state |= STATE_ON_HANDSHAKE;
  return 0;
}

static void _on_closed(struct iwn_grpc_client_ctx *cc) {
  _ctx.state |= STATE_ON_CLOSED;
}

static void _on_error(struct iwn_grpc_client_ctx *cc) {
  _ctx.state |= STATE_ON_ERROR;
}

static void _on_destroy(struct iwn_grpc_client_ctx *cc) {
  _ctx.state |= STATE_ON_DESTROY;
}

static iwrc _iwn_val_init(struct iwn_val *val, const char *hex) {
  memset(val, 0, sizeof(*val));
  size_t hexlen = strlen(hex);
  size_t nbytes = hexlen / 2;
  if (nbytes * 2 != hexlen) {
    return IW_ERROR_INVALID_ARGS;
  }
  char *buf = malloc(nbytes);
  if (!buf) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  val->len = iwhex2bin(hex, hexlen, buf, nbytes);
  val->buf = buf;
  return 0;
};

static void _iwn_val_destroy(struct iwn_val *val) {
  iwn_val_buf_free(val);
}

struct _req_test_ctx1 {
  iwrc rc;
  struct iwpool  *pool;
  const char     *error;
  struct iwn_vals vals;
  uint32_t state;
  uint32_t num_drains;
  uint32_t req_id;
  bool     closed;
};

static void _req_on_destroy_impl(struct _req_test_ctx1 *rctx) {
  IWN_ASSERT(rctx);
  if (rctx) {
    iwpool_destroy(rctx->pool);
  }
}

static void _req_on_destroy1(const struct iwn_grpc_req_ctx *rctx) {
  _req_on_destroy_impl(rctx->spec.user_data);
}

static void _req_on_closed1(const struct iwn_grpc_req_ctx *rctx) {
  struct _req_test_ctx1 *tctx = rctx->spec.user_data;
  IWN_ASSERT(!tctx->closed);
  tctx->closed = true;
  // Request closed now terminate grpc client session
  bool ret = iwn_grpc_client_close(rctx->client_ctx.client);
  IWN_ASSERT(ret);
}

static void _req_on_error1(const struct iwn_grpc_req_ctx *ctx) {
  struct _req_test_ctx1 *tctx = ctx->spec.user_data;
  IWN_ASSERT(!tctx->rc);
  IWN_ASSERT(!tctx->error);
  IWN_ASSERT(ctx->rc);
  tctx->rc = ctx->rc;
  if (ctx->error_explained) {
    tctx->error = iwpool_strdup2(tctx->pool, ctx->error_explained);
  }
  iwlog_ecode_error(ctx->rc, "_req_on_error: %s", (ctx->error_explained ? ctx->error_explained : ""));
}

static void _req_on_outgoing_messages_queue_drained1(struct iwn_grpc_req_ctx *rctx) {
  struct _req_test_ctx1 *tctx = rctx->spec.user_data;
  ++tctx->num_drains;
}

static void _req_on_message1(struct iwn_grpc_req_message *msg, bool *cont) {
  struct _req_test_ctx1 *tctx = msg->ctx.spec.user_data;
  IWN_ASSERT_FATAL(iwn_vals_add_val(tctx->pool, &tctx->vals, &msg->msg, true));
  // Got it now close the request
  iwn_grpc_client_request_close(&msg->ctx);
}

static iwrc _run_test1(void) {
  iwrc rc = 0;

  // grpcurl -plaintext -import-path . -proto ./helloworld.proto -d '{"name":"Anton"}'  localhost:50051
  // helloworld.Greeter/SayHello
  // Message: name:"Anton": 0a05416e746f6e

  struct iwn_grpc_req_spec spec = {
    .client = _ctx.client,
    .path = "helloworld.Greeter/SayHello",
    .on_error = _req_on_error1,
    .on_message = _req_on_message1,
    .on_outgoing_messages_queue_drained = _req_on_outgoing_messages_queue_drained1,
    .on_closed = _req_on_closed1,
    .on_destroy = _req_on_destroy1,
    
  };
  struct iwn_val val;
  RCC(rc, finish, _iwn_val_init(&val, "0a05416e746f6e"));

  struct iwpool *pool = iwpool_create_empty();
  RCB(finish, pool);

  struct _req_test_ctx1 *rctx = iwpool_calloc(sizeof(*rctx), pool);
  RCB(finish, rctx);

  rctx->pool = pool;
  spec.user_data = rctx;

  rc = iwn_grpc_client_request_open(&spec, &val, 0, &rctx->req_id);

finish:
  _iwn_val_destroy(&val);
  if (rc) {
    iwlog_ecode_error3(rc);
    _req_on_destroy_impl(rctx);
  }
  return rc;
}

static iwrc _run_tests(void) {
  iwrc rc;
  IWN_ASSERT(!(rc = _run_test1()));
  return rc;
}

int main(int argc, char *argv[]) {
  ssize_t len;

  iwrc rc = iwn_grpc_init();
  RCRET(rc);

  struct iwpool *pool = iwpool_create_empty();
  RCB(finish, pool);
  _ctx.pool = pool;

  struct iwn_grpc_client_spec spec = {
    .url = "grpc+plaintext://localhost:50051",
    .on_handshake = _on_handshake,
    .on_closed = _on_closed,
    .on_error = _on_error,
    .on_destroy = _on_destroy,
  };

  RCC(rc, finish, iwn_poller_create(3, 1, &_ctx.poller));

  spec.poller = _ctx.poller;
  RCC(rc, finish, iwn_grpc_client_open(&spec, &_ctx.client));

  pthread_t poll_thread = 0;
  RCC(rc, finish, iwn_poller_poll_in_thread(_ctx.poller, "poller", &poll_thread));

  rc = _run_tests();

  if (rc) {
    iwn_poller_shutdown_request(_ctx.poller);
  }
  pthread_join(poll_thread, 0);

finish:
  if (rc) {
    iwlog_ecode_error3(rc);
  }
  IWN_ASSERT(rc == 0);
  _ctx_destroy();
  return iwn_assertions_failed > 0 ? 1 : 0;
}

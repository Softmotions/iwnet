#include "iwtests.h"
#include "iwn_grpc_client.h"
#include "iwn_poller.h"
#include "iwstepbox.h"

#include <iowow/iwarr.h>
#include <iowow/iwconv.h>
#include <iowow/iwlog.h>
#include <iowow/iwpool.h>
#include <stdio.h>
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

static int _grpc_port = 50051;
static bool _grpc_ssl = false;

static void _grpc_url(char *buf, size_t buflen) {
  snprintf(buf, buflen, _grpc_ssl ? "grpc://localhost:%d" : "grpc+plaintext://localhost:%d", _grpc_port);
}

static void _parse_args(int argc, char *argv[]) {
  for (int i = 0; i < argc; ++i) {
    const char *arg = argv[i];
    if (!strcmp(arg, "--ssl")) {
      _grpc_ssl = true;
    } else if (!strcmp(arg, "--port") && i + 1 < argc) {
      char *end = 0;
      long v = strtol(argv[++i], &end, 10);
      if (!end || *end != '\0' || v <= 0 || v > 65535) {
        IW_TEST_FAILF("Invalid port: %s", argv[i]);
        return;
      }
      _grpc_port = (int) v;
    } else {
      IW_TEST_FAILF("Unknown option: %s, expected --port PORT or --ssl", arg);
      return;
    }
  }
}

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
  IW_TEST_ASSERT(cc->rc);
  if (cc->rc) {
    iwlog_ecode_error2(cc->rc, "on_error");
  }
}

static void _on_destroy(struct iwn_grpc_client_ctx *cc) {
  IW_TEST_ASSERT(_ctx.client == cc->client);
  _ctx.client = 0;
  iw_stepbox_on(&sbox[0], STEP_ON_DESTROY, 1);
}

static void _iwn_val_init(struct iwn_val *val, const char *hex) {
  memset(val, 0, sizeof(*val));
  size_t hexlen = strlen(hex);
  size_t nbytes = hexlen / 2;
  IW_TEST_ASSERT_FATAL(nbytes * 2 == hexlen);
  char *buf = malloc(nbytes);
  IW_TEST_ASSERT_FATAL(buf);
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
  IW_TEST_ASSERT(tctx);
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
  IW_TEST_ASSERT(ret);
}

static void _req_on_error(struct iwn_grpc_req_ctx *ctx) {
  iw_stepbox_on(&sbox[0], STEP_REQ_ON_ERROR, 1);
  struct _req_test_ctx *tctx = ctx->spec.user_data;
  IW_TEST_ASSERT(!tctx->rc);
  IW_TEST_ASSERT(!tctx->error);
  IW_TEST_ASSERT(ctx->rc);
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
  IW_TEST_ASSERT(rc == 0);
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

/// Opens the gRPC client session and starts the poller thread.
/// The test options are taken from the arguments given after `--`.
static iwrc _grpc_test_setup(pthread_t *poll_thread) {
  iwrc rc = 0;
  char url[128];

  _signals_setup();
  _parse_args(iw_test_argc, iw_test_argv);
  if (iw_test_failures() > 0) {
    /* The option errors are reported already, connecting makes no sense. */
    return IW_ERROR_INVALID_CMD_ARGS;
  }

  _grpc_url(url, sizeof(url));

  RCC(rc, finish, iwn_grpc_init());
  RCB(finish, _ctx.pool = iwpool_create_empty());

  struct iwn_grpc_client_spec spec = {
    .url = url,
    .on_handshake = _on_handshake,
    .on_closed = _on_closed,
    .on_error = _on_error,
    .on_destroy = _on_destroy,
  };

  RCC(rc, finish, iwn_poller_create(3, 1, &_ctx.poller));
  spec.poller = _ctx.poller;
  RCC(rc, finish, iwn_grpc_client_open(&spec, &_ctx.client));
  RCC(rc, finish, iwn_poller_poll_in_thread(_ctx.poller, "poller", poll_thread));

finish:
  if (rc) {
    iwlog_ecode_error3(rc);
    /* Release the partially created context, the case will not run. */
    _ctx_destroy();
  }
  return rc;
}

/// Releases the gRPC client session and its resources.
static void _grpc_test_teardown(void) {
  _ctx_destroy();
}

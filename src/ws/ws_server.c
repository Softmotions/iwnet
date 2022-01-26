#include "ws_server.h"
#include "utils/base64.h"

#include <iowow/iwlog.h>
#include <iowow/iwxstr.h>
#include <bearssl_hash.h>
#include <wslay/wslay.h>

#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <errno.h>

struct ctx {
  struct iwn_ws_sess   sess;
  struct iwn_http_req *hreq;
  struct iwn_ws_handler_spec *spec;
};

void iwn_ws_server_handler_dispose(struct iwn_wf_ctx *ctx, void *user_data) {
  struct iwn_ws_handler_spec *spec = user_data;
  if (spec && spec->handler_spec_dispose) {
    spec->handler_spec_dispose(spec);
  }
}

static void _ctx_destroy(struct ctx *ctx) {
  if (ctx) {
    if (ctx->hreq->_ws_data == ctx) {
      ctx->hreq->_ws_data = 0;
    }
    if (ctx->spec && ctx->spec->on_session_dispose) {
      ctx->spec->on_session_dispose(&ctx->sess);
    }
    free(ctx);
  }
}

static void _on_request_dispose(struct iwn_http_req *hreq) {
  struct ctx *ctx = hreq->_ws_data;
  if (ctx) {
    _ctx_destroy(ctx);
  }
}

static bool _sess_transfer_io_events(struct iwn_http_req *hreq) {
  /// Transfer IO events to our wslay layer

  // TODO:

  return true;
}

int iwn_ws_server_handler(struct iwn_wf_req *req, void *user_data) {
  iwrc rc = 0;
  int rv = -1;

  struct ctx *ctx = 0;
  struct iwn_http_req *hreq = req->http;
  struct iwn_ws_handler_spec *spec = user_data;

  if (!spec) {
    iwlog_error2("Missing user data for iwn_ws_server_handler");
    return -1;
  }
  if (hreq->on_request_dispose) {
    iwlog_ecode_error2(IW_ERROR_ASSERTION, "(struct iwn_http_req).on_request_dispose should not be initialized before");
    return -1;
  }
  if (hreq->on_response_completed) {
    iwlog_ecode_error2(IW_ERROR_ASSERTION,
                       "(struct iwn_http_req).on_response_completed should not be initialized before");
    return -1;
  }

  struct iwn_val val = iwn_http_request_header_get(hreq, "upgrade", IW_LLEN("upgrade"));
  if (val.len != IW_LLEN("websocket") || strncasecmp(val.buf, "websocket", val.len) != 0) {
    goto finish;
  }
  val = iwn_http_request_header_get(hreq, "sec-websocket-version", IW_LLEN("sec-websocket-version"));
  if (val.len != IW_LLEN("13") || strncmp(val.buf, "13", val.len) != 0) {
    goto finish;
  }
  struct iwn_val ws_key = iwn_http_request_header_get(hreq, "sec-websocket-key", IW_LLEN("sec-websocket-key"));
  if (!ws_key.len) {
    goto finish;
  }

  RCC(rc, finish, iwn_http_response_header_set(hreq, "upgrade", "websocket", IW_LLEN("websocket")));

  struct iwn_val ws_protocol
    = iwn_http_request_header_get(hreq, "sec-websocket-protocol", IW_LLEN("sec-websocket-protocol"));
  if (ws_protocol.len) {
    RCC(rc, finish, iwn_http_response_header_set(hreq, "sec-websocket-protocol", ws_protocol.buf, ws_protocol.len));
  }

  {
    size_t len = ws_key.len;
    unsigned char buf[len + IW_LLEN(WS_MAGIC13)];
    unsigned char sbuf[br_sha1_SIZE];
    char vbuf[br_sha1_SIZE * 2];
    memcpy(buf, ws_key.buf, len);
    memcpy(buf + len, WS_MAGIC13, IW_LLEN(WS_MAGIC13));
    br_sha1_context ctx;
    br_sha1_init(&ctx);
    br_sha1_update(&ctx, buf, sizeof(buf));
    br_sha1_out(&ctx, sbuf);
    if (!iwn_base64_encode(vbuf, sizeof(vbuf), &len, sbuf, sizeof(sbuf), base64_VARIANT_ORIGINAL)) {
      goto finish;
    }
    RCC(rc, finish, iwn_http_response_header_set(hreq, "sec-websocket-accept", vbuf, len));
  }

  RCA(ctx = calloc(1, sizeof(*ctx)), finish);
  ctx->hreq = hreq;
  ctx->sess.req = req;
  ctx->spec = ctx->sess.spec = spec;

  hreq->_ws_data = ctx;
  hreq->on_request_dispose = _on_request_dispose;
  hreq->on_response_completed = _sess_transfer_io_events;

  if (iwn_http_response_write(hreq, 101, "", 0, 0, 0)) {
    rv = 1;
  }

finish:
  if (rc) {
    _ctx_destroy(ctx);
    iwlog_ecode_error3(rc);
    return -1;
  }
  return rv;
}

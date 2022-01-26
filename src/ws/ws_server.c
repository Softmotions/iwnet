#include "ws_server.h"
#include "utils/base64.h"

#include <iowow/iwlog.h>
#include <iowow/iwxstr.h>
#include <bearssl_hash.h>
#include <wslay/wslay.h>

#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <pthread.h>
#include <errno.h>
#include <assert.h>

struct ctx {
  struct iwn_ws_sess   sess;
  struct iwn_http_req *hreq;
  struct iwn_ws_handler_spec *spec;
  struct iwn_poller_adapter  *pa;
  wslay_event_context_ptr     wc;
  pthread_mutex_t mtx;
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
    wslay_event_context_free(ctx->wc);
    pthread_mutex_destroy(&ctx->mtx);
    free(ctx);
  }
}

static void _on_request_dispose(struct iwn_http_req *hreq) {
  struct ctx *ctx = hreq->_ws_data;
  if (ctx) {
    _ctx_destroy(ctx);
  }
}

static void _wslay_msg_recv_callback(
  wslay_event_context_ptr                   wctx,
  const struct wslay_event_on_msg_recv_arg *arg,
  void                                     *user_data
  ) {
  struct ctx *ctx = user_data;
  if (wslay_is_ctrl_frame(arg->opcode)) {
    return;
  }
  if (arg->msg_length && ctx->spec->msg_handler) {
    if (!ctx->spec->msg_handler(&ctx->sess, (void*) arg->msg, arg->msg_length)) {
      iwn_poller_remove(ctx->pa->poller, ctx->pa->fd);
    }
  }
}

static ssize_t _wslay_recv_callback(
  wslay_event_context_ptr wctx,
  uint8_t                *buf,
  size_t                  len,
  int                     flags,
  void                   *user_data
  ) {
  ssize_t rci = -1;
  struct ctx *ctx = user_data;
  struct iwn_poller_adapter *pa = ctx->pa;
  assert(pa);

again:
  rci = pa->read(pa, buf, len);
  if (rci == -1) {
    if (errno == EINTR) {
      goto again;
    }
    if (errno == EAGAIN) {
      wslay_event_set_error(ctx->wc, WSLAY_ERR_WOULDBLOCK);
    } else {
      wslay_event_set_error(ctx->wc, WSLAY_ERR_CALLBACK_FAILURE);
    }
  } else if (rci == 0) {
    errno = EIO;
    rci = -1;
  }
  return rci;
}

static ssize_t _wslay_send_callback(
  wslay_event_context_ptr wctx,
  const uint8_t          *buf,
  size_t                  len,
  int                     flags,
  void                   *user_data
  ) {
  ssize_t rci = -1;
  struct ctx *ctx = user_data;
  struct iwn_poller_adapter *pa = ctx->pa;
  assert(pa);

again:
  rci = pa->write(pa, buf, len);
  if (rci == -1) {
    if (errno == EINTR) {
      goto again;
    }
    if (errno == EAGAIN) {
      wslay_event_set_error(ctx->wc, WSLAY_ERR_WOULDBLOCK);
    } else {
      wslay_event_set_error(ctx->wc, WSLAY_ERR_CALLBACK_FAILURE);
    }
  } else if (rci == 0) {
    errno = EIO;
    rci = -1;
  }
  return rci;
}

static int64_t _on_poller_adapter_event(struct iwn_poller_adapter *pa, void *user_data, uint32_t events) {
  struct iwn_http_req *hreq = user_data;
  struct ctx *ctx = hreq->_ws_data;
  int64_t ret = -1;

  if (ctx->pa != pa) {
    ctx->pa = pa;
  }

  pthread_mutex_lock(&ctx->mtx);

  if (wslay_event_want_write(ctx->wc) && wslay_event_send(ctx->wc) < 0) {
    goto finish;
  }
  if (wslay_event_want_read(ctx->wc) && wslay_event_recv(ctx->wc) < 0) {
    goto finish;
  }

  ret = 0;
  if (wslay_event_want_read(ctx->wc)) {
    ret |= IWN_POLLIN;
  }
  if (wslay_event_want_write(ctx->wc)) {
    ret |= IWN_POLLOUT;
  }

  if (ret == 0) {
    ret = -1;
  }

finish:
  pthread_mutex_unlock(&ctx->mtx);
  return ret;
}

static bool _inject_wslay_poller_handler(struct iwn_http_req *hreq) {
  struct ctx *ctx = hreq->_ws_data;
  if (wslay_event_context_server_init(&ctx->wc, &(struct wslay_event_callbacks) {
    .recv_callback = _wslay_recv_callback,
    .send_callback = _wslay_send_callback,
    .on_msg_recv_callback = _wslay_msg_recv_callback
  }, ctx)) {
    return false;
  }
  iwn_http_inject_poller_event_handler(hreq, _on_poller_adapter_event);
  return true;
}

bool iwn_ws_server_write_text(struct iwn_ws_sess *sess, const char *buf, size_t buf_len) {
  struct ctx *ctx = (void*) sess;
  if (!ctx || !buf) {
    return false;
  }
  if (buf_len == 0) {
    return true;
  }
  pthread_mutex_lock(&ctx->mtx);
  if (wslay_event_queue_msg(ctx->wc, &(struct wslay_event_msg) {
    .opcode = WSLAY_TEXT_FRAME,
    .msg = (void*) buf,
    .msg_length = buf_len
  })) {
    pthread_mutex_unlock(&ctx->mtx);
    return false;
  }
  bool ret = 0 == iwn_poller_arm_events(ctx->pa->poller, ctx->pa->fd, IWN_POLLOUT | IWN_POLLET);
  pthread_mutex_unlock(&ctx->mtx);
  return ret;
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

    br_sha1_context sha1;
    br_sha1_init(&sha1);
    br_sha1_update(&sha1, buf, sizeof(buf));
    br_sha1_out(&sha1, sbuf);

    if (!iwn_base64_encode(vbuf, sizeof(vbuf), &len, sbuf, sizeof(sbuf), base64_VARIANT_ORIGINAL)) {
      goto finish;
    }
    RCC(rc, finish, iwn_http_response_header_set(hreq, "sec-websocket-accept", vbuf, len));
  }

  RCA(ctx = calloc(1, sizeof(*ctx)), finish);
  ctx->hreq = hreq;
  ctx->sess.req = req;
  ctx->spec = ctx->sess.spec = spec;
  memcpy(&ctx->mtx, &(pthread_mutex_t) PTHREAD_MUTEX_INITIALIZER, sizeof(ctx->mtx));

  hreq->_ws_data = ctx;
  hreq->on_request_dispose = _on_request_dispose;
  hreq->on_response_completed = _inject_wslay_poller_handler;

  iwn_http_connection_set_upgrade(hreq);
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

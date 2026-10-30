#include "iwn_grpc_server.h"
#include "iwn_url.h"
#include "ssl/iwn_brssl_poller_adapter.h"
#include "poller/iwn_direct_poller_adapter.h"

#include <iowow/iwrefs.h>
#include <iowow/iwlog.h>
#include <iowow/iwpool.h>
#include <iowow/iwxstr.h>
#include <iowow/iwarr.h>
#include <iowow/iwhmap.h>

#include <hive.h>
#include <string.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netdb.h>
#include <unistd.h>

#ifdef IW_BLOCKS
#include <Block.h>
#endif

#define _FLAG_SECURE     0x100U
#define _FLAG_NO_NETWORK 0x200U

enum _rx_state {
  _RX_HEADER,
  _RX_BODY,
  _RX_STOP,
};

enum _resp_state {
  _RESP_NONE,
  _RESP_STREAMING,
  _RESP_END_PENDING,
  _RESP_ENDED,
};

struct _rx {
  enum _rx_state state;
  /// gRPC message prefix: 1 byte compressed flag + 4 bytes big-endian length.
  uint8_t header[5];
  size_t  header_len;

  uint32_t       body_len;
  struct iwxstr *body;
  uint8_t compressed;
};

struct _io_writev_state {
  struct iovec *iov;
  int iovcnt;
};

struct _msg_slot {
  struct iwpool    *pool;
  struct iwn_vals   vals;
  struct _msg_slot *next;
};

struct _deferred_callback;

struct iwn_grpc_server_conn {
  struct iwref_holder     ref;
  struct iwn_grpc_server *server;
  struct iwpool *pool;
  struct iwn_poller_adapter *pa;
  struct hive_session       *sess;
  struct hive_callbacks      hive_callbacks;
  struct hive_options       *hive_options;
  struct iwxstr *input_buf;
  struct iwhmap *requests_map;
  struct iwulist deferred_callbacks;

  pthread_mutex_t mtx;

  int      fd;
  unsigned flags;

  bool io_wouldblock;
  bool io_progress;     ///< Last send round wrote at least one byte into the transport.
  bool send_blocked;    ///< Response data sources are blocked by the HTTP/2 flow-control window.

  volatile iwrc rc;
  volatile bool pa_closed;       ///< Poller adapter is not operable in this state.
  volatile bool in_loop;         ///< True if we are inside event loop callbacks.
  volatile bool goaway_submitted;
  bool error_reported;
};

struct _server_req {
  struct iwref_holder ref;
  struct iwn_grpc_server_req   ctx;
  struct iwn_grpc_server_conn *conn;
  struct iwpool *pool;
  struct _rx     rx;
  struct _msg_slot       *mslots;
  struct hive_data_source data_source;

  int  grpc_status;
  iwrc rc;
  enum _resp_state resp_state;
  const char *error_explained;

  bool headers_done;
  bool req_started;
  bool remote_end;
  bool src_finished;
  volatile bool cancel_pending;
};

struct _deferred_callback {
  struct iwn_grpc_server_conn *conn;
  iwrc     (*execute)(const struct _deferred_callback*);
  uint64_t error_code;
  uint32_t stream_id;
  bool     immediate; ///< Try execute deferred callback immediately.
};

struct iwn_grpc_server {
  struct iwref_holder ref;
  struct iwn_poller  *poller;
  struct iwpool      *pool;
  struct iwn_url      url;

  struct iwn_grpc_server_spec spec;

  pthread_mutex_t mtx;
  struct iwhmap  *conns_map; ///< fd -> iwn_grpc_server_conn

  int      listen_fd;
  unsigned flags;

  bool opened;

  volatile bool closed_by_api;
};

static void _req_pub_update(struct _server_req *req);

static iwrc _req_submit_trailers_locked(struct _server_req *req);
static iwrc _req_write_headers_locked(struct _server_req *req, const char *encoding);
static iwrc _req_end_locked(struct _server_req *req, iwrc rc, const char *message);

static void _conn_ctx_init(struct iwn_grpc_server_conn *conn, struct iwn_grpc_server_conn_ctx *ctx) {
  memset(ctx, 0, sizeof(*ctx));
  ctx->rc = conn->rc;
  ctx->pa = conn->pa;
  ctx->server = conn->server;
  ctx->conn = conn;
  ctx->user_data = conn->server->spec.user_data;
}

static iwrc _hrc2rc(int err) {
  if (!err) {
    return 0;
  }
  switch (err) {
    case HIVE_ERR:
      return IW_ERROR_FAIL;
    case HIVE_ERR_NOMEM:
      return IW_ERROR_ALLOC;
    case HIVE_ERR_INVALID_ARG:
      return IW_ERROR_INVALID_ARGS;
    case HIVE_ERR_PROTOCOL:
    case HIVE_H2_PROTOCOL_ERROR:
      return GRPC_ERROR_H2_PROTOCOL;
    case HIVE_ERR_COMPRESSION:
    case HIVE_H2_COMPRESSION_ERROR:
      return GRPC_ERROR_H2_COMPRESSION;
    case HIVE_ERR_FLOW_CONTROL:
      return GRPC_ERROR_H2_FLOW_CONTROL;
    case HIVE_H2_REFUSED_STREAM:
      return GRPC_ERROR_H2_REFUSED_STREAM;
    case HIVE_ERR_STREAM_CLOSED:
    case HIVE_H2_STREAM_CLOSED:
      return GRPC_ERROR_H2_STREAM_CLOSED;
    case HIVE_ERR_SESSION_CLOSED:
      return IW_ERROR_INVALID_STATE;
    case HIVE_H2_SETTINGS_TIMEOUT:
      return GRPC_ERROR_H2_TIMEOUT;
    case HIVE_H2_CANCEL:
      return GRPC_ERROR_H2_CANCEL;
    default:
      if (err < 0) {
        return GRPC_ERROR;
      } else {
        return GRPC_ERROR_H2;
      }
  }
}

static int _rc2grpc(iwrc rc) {
  switch (rc) {
    case 0:
      return 0;
    case GRPC_ERROR_CANCELLED:
      return 1;
    case GRPC_ERROR:
      return 2;
    case GRPC_ERROR_INVALID_ARGUMENT:
      return 3;
    case GRPC_ERROR_DEADLINE_EXCEEDED:
      return 4;
    case GRPC_ERROR_NOT_FOUND:
      return 5;
    case GRPC_ERROR_ALREADY_EXISTS:
      return 6;
    case GRPC_ERROR_PERMISSION_DENIED:
      return 7;
    case GRPC_ERROR_RESOURCE_EXHAUSTED:
      return 8;
    case GRPC_ERROR_FAILED_PRECONDITION:
      return 9;
    case GRPC_ERROR_ABORTED:
      return 10;
    case GRPC_ERROR_OUT_OF_RANGE:
      return 11;
    case GRPC_ERROR_UNIMPLEMENTED:
      return 12;
    case GRPC_ERROR_INTERNAL:
      return 13;
    case GRPC_ERROR_UNAVAILABLE:
      return 14;
    case GRPC_ERROR_DATA_LOSS:
      return 15;
    case GRPC_ERROR_UNAUTHENTICATED:
      return 16;
    default:
      return 2; // UNKNOWN
  }
}

/// gRPC `grpc-message` header percent encoding.
static const char* _percent_encode(struct iwpool *pool, const char *str) {
  if (!str) {
    return 0;
  }
  static const char hex[] = "0123456789ABCDEF";
  size_t len = strlen(str);
  char *out = iwpool_alloc(len * 3 + 1, pool);
  if (!out) {
    return 0;
  }
  char *wp = out;
  for (const unsigned char *p = (const unsigned char*) str; *p; ++p) {
    if (*p >= 0x20 && *p <= 0x7e && *p != '%') {
      *wp++ = (char) *p;
    } else {
      *wp++ = '%';
      *wp++ = hex[*p >> 4];
      *wp++ = hex[*p & 0x0f];
    }
  }
  *wp = '\0';
  return out;
}

static inline bool _hive_rc_is_ok_for_io(int hrc) {
  return hrc == HIVE_OK || hrc == HIVE_ERR_WOULDBLOCK;
}

static void _msg_slot_destroy(struct _msg_slot *slot) {
  if (slot && slot->pool) {
    iwpool_destroy(slot->pool);
  }
}

static iwrc _msg_slot_create(
  struct _server_req   *req,
  const struct iwn_val *msg,
  bool                  compressed,
  struct _msg_slot    **out) {
  iwrc rc = 0;
  struct _msg_slot *slot;
  struct iwpool *pool = 0;
  size_t mlen = 0;
  uint32_t max_message_bytes = req->conn->server->spec.grpc.max_message_bytes;

  *out = 0;

  for (const struct iwn_val *v = msg; v; v = v->next) {
    if (v->len > max_message_bytes) {
      return GRPC_ERROR_MSG_TOO_LARGE;
    }
    mlen += sizeof(*v) + v->len + sizeof(uint32_t) + 1 /*compressed*/;
  }

  pool = iwpool_create_attach(req->pool, sizeof(*slot) + mlen);
  if (!pool) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }

  RCB(finish, slot = iwpool_calloc(sizeof(*slot), pool));
  slot->pool = pool;

  for (const struct iwn_val *v = msg; v; v = v->next) {
    struct iwn_val *nv;
    RCB(finish, nv = iwpool_calloc(sizeof(*nv), pool));
    nv->len = v->len + sizeof(uint32_t) + 1 /* compressed */;
    RCB(finish, nv->buf = iwpool_alloc(nv->len, pool));

    char *wp = nv->buf;
    uint32_t mlen = v->len;
#ifndef IW_BIGENDIAN
    mlen = IW_SWAB32(mlen);
#endif

    *wp = compressed ? 1 : 0; /* compressed flag */
    ++wp;

    memcpy(wp, &mlen, sizeof(mlen));
    wp += sizeof(mlen);
    if (v->len) {
      memcpy(wp, v->buf, v->len);
    }

    if (slot->vals.last) {
      slot->vals.last->next = nv;
      slot->vals.last = nv;
    } else {
      slot->vals.first = nv;
      slot->vals.last = nv;
    }
  }

finish:
  if (rc) {
    iwpool_destroy(pool);
  } else {
    *out = slot;
  }
  return rc;
}

static inline void _hive_nv_set(hive_nv_t *nv, const char *name, const char *value, uint8_t flags) {
  nv->name = (const uint8_t*) name;
  nv->value = (const uint8_t*) value;
  nv->name_len = strlen(name);
  nv->value_len = strlen(value);
  nv->flags = flags;
}

static void _io_consume_iov(struct _io_writev_state *st, size_t written) {
  while (st->iovcnt > 0 && written > 0) {
    if (written >= st->iov[0].iov_len) {
      written -= st->iov[0].iov_len;
      st->iov++;
      st->iovcnt--;
    } else {
      st->iov[0].iov_base = (char*) st->iov[0].iov_base + written;
      st->iov[0].iov_len -= written;
      written = 0;
    }
  }
}

static int _io_flush_writev(struct iwn_poller_adapter *pa, struct _io_writev_state *st, ssize_t *out_acc_written) {
  while (st->iovcnt > 0) {
    if (st->iov[0].iov_len == 0) {
      st->iov++;
      st->iovcnt--;
      continue;
    }
    ssize_t ret = pa->write(pa, st->iov[0].iov_base, st->iov[0].iov_len);
    if (ret > 0) {
      _io_consume_iov(st, (size_t) ret);
      *out_acc_written = *out_acc_written + ret;
      continue;
    }
    if (ret == -1 && errno == EINTR) {
      continue;
    }
    if (ret == -1 && (errno == EWOULDBLOCK || errno == EAGAIN)) {
      return 0;
    }
    return -1;
  }
  return 1;
}

static ssize_t _hcb_io_send(
  hive_session_t     *session,
  const struct iovec *iov_,
  int                 iovcnt,
  void               *user_data) {
  struct iwn_grpc_server_conn *conn = user_data;
  if (!conn->pa || iovcnt < 1) {
    return 0;
  }

  struct iovec iov[iovcnt];
  for (int i = 0; i < iovcnt; ++i) {
    iov[i] = iov_[i];
  }

  ssize_t total = 0;
  int rci = _io_flush_writev(conn->pa, &(struct _io_writev_state) { iov, iovcnt }, &total);
  if (rci == -1) {
    return -1;
  }
  if (rci == 0) {
    conn->io_wouldblock = true;
  }
  if (total > 0) {
    conn->io_progress = true;
  }
  return total;
}

static int _conn_deferred_register(struct iwn_grpc_server_conn *conn, const struct _deferred_callback *cb) {
  if (conn->pa_closed) {
    return 0;
  }
  if (cb->immediate && !conn->in_loop) {
    iwrc rc = cb->execute(cb);
    if (rc && !(conn->server->spec.flags & IWN_GRPC_LOG_QUIET)) {
      iwlog_ecode_error2(rc, "grpc | API callback failed");
    }
    return 1;
  }
  pthread_mutex_lock(&conn->mtx);
  int rc = iwulist_push(&conn->deferred_callbacks, cb);
  pthread_mutex_unlock(&conn->mtx);
  return rc ? 0 : 1;
}

static iwrc _conn_deferred_execute(struct iwn_grpc_server_conn *conn) {
  iwrc rc = 0;
  struct iwulist tasks = { .usize = sizeof(struct _deferred_callback) };
  pthread_mutex_lock(&conn->mtx);
  rc = iwulist_copy(&conn->deferred_callbacks, &tasks);
  if (rc) {
    pthread_mutex_unlock(&conn->mtx);
    iwulist_destroy_keep(&tasks);
    return rc;
  }
  iwulist_reset(&conn->deferred_callbacks);
  pthread_mutex_unlock(&conn->mtx);
  for (int i = 0; i < tasks.num; ++i) {
    struct _deferred_callback *t = iwulist_get(&tasks, i);
    iwrc trc = t->execute(t);
    if (trc) {
      if (!rc) {
        rc = trc;
      }
      if (!(conn->server->spec.flags & IWN_GRPC_LOG_QUIET)) {
        iwlog_ecode_error2(rc, "grpc | API callback failed");
      }
    }
  }
  iwulist_destroy_keep(&tasks);
  return rc;
}

static void _rx_init(struct _rx *rx) {
  memset(rx, 0, sizeof(*rx));
  rx->state = _RX_HEADER;
}

static void _rx_destroy(struct _rx *rx) {
  iwxstr_destroy(rx->body);
  memset(rx, 0, sizeof(*rx));
}

static void _rx_reset(struct _rx *rx) {
  struct iwxstr *body = rx->body;
  memset(rx, 0, sizeof(*rx));
  rx->body = body;
}

///////////////////////////////////////////////////////////////////////////
//                              Request                                    //
///////////////////////////////////////////////////////////////////////////

static void _req_pub_update(struct _server_req *req) {
  _conn_ctx_init(req->conn, &req->ctx.conn_ctx);
  req->ctx.rc = req->rc;
  req->ctx.impl = req;
}

static ssize_t _req_read_callback(
  hive_session_t     *session,
  uint32_t            stream_id,
  uint8_t           **buf,
  size_t              length,
  uint32_t           *data_flags,
  hive_data_source_t *source,
  void               *user_data) {
  (void) session;
  (void) stream_id;
  (void) user_data;

  struct _server_req *req = source ? source->ptr : 0;
  if (!req) {
    return HIVE_ERR;
  }

  struct iwn_val *v = 0;
  if (!req->mslots) {
    if (req->resp_state == _RESP_END_PENDING) {
      // Detach the data source; trailers are submitted separately.
      req->src_finished = true;
      return 0;
    }
    return HIVE_ERR_WOULDBLOCK;
  }

  v = req->mslots->vals.first;
  while (v && v->cnt == v->len) {
    v = v->next;
    req->mslots->vals.first = v;
  }

  while (!v) {
    struct _msg_slot *old = req->mslots;
    req->mslots = old ? old->next : 0;
    if (old) {
      _msg_slot_destroy(old);
    }
    if (req->mslots) {
      v = req->mslots->vals.first;
      continue;
    }
    if (req->resp_state == _RESP_END_PENDING) {
      req->src_finished = true;
      return 0;
    }
    return HIVE_ERR_WOULDBLOCK;
  }

  uint8_t *ptr = (uint8_t*) v->buf + v->cnt;
  ssize_t m = v->len - v->cnt;
  ssize_t n = MIN(m, length);
  v->cnt += n;

  if (v->cnt < v->len || v->next || req->mslots->next) {
    *data_flags = *data_flags | HIVE_DATA_FLAG_NO_COPY;
    *buf = ptr;
  } else {
    struct _msg_slot *slot = req->mslots;
    req->mslots = slot->next;
    memcpy(*buf, ptr, n);
    _msg_slot_destroy(slot);
  }
  return n;
}

static iwrc _req_write_headers_locked(struct _server_req *req, const char *encoding) {
  if (req->resp_state != _RESP_NONE) {
    return 0;
  }
  struct iwn_grpc_server *server = req->conn->server;
  struct hive_nv nva[8];
  size_t n = 0;

  _hive_nv_set(&nva[n++], ":status", "200", 0);
  _hive_nv_set(&nva[n++], "content-type", "application/grpc+proto", 0);
  _hive_nv_set(&nva[n++], "grpc-accept-encoding", server->spec.grpc.accept_encoding, 0);
  _hive_nv_set(&nva[n++], "grpc-encoding", encoding && *encoding ? encoding : "identity", 0);

  req->data_source.read_callback = _req_read_callback;
  req->data_source.ptr = req;

  iwrc rc = _hrc2rc(hive_submit_response(req->conn->sess, req->ctx.stream_id, nva, n, &req->data_source));
  if (rc) {
    req->data_source.read_callback = 0;
    req->data_source.ptr = 0;
  } else {
    req->resp_state = _RESP_STREAMING;
  }
  return rc;
}

static iwrc _req_submit_trailers_locked(struct _server_req *req) {
  if (req->resp_state == _RESP_ENDED) {
    return 0;
  }
  char status[16];
  snprintf(status, sizeof(status), "%d", req->grpc_status);

  struct hive_nv nva[3];
  size_t n = 0;
  _hive_nv_set(&nva[n++], "grpc-status", status, 0);
  if (req->error_explained) {
    _hive_nv_set(&nva[n++], "grpc-message", req->error_explained, 0);
  }

  iwrc rc = _hrc2rc(hive_submit_trailers(req->conn->sess, req->ctx.stream_id, nva, n));
  req->resp_state = _RESP_ENDED;
  req->src_finished = true;
  return rc;
}

static iwrc _req_end_locked(struct _server_req *req, iwrc rc, const char *message) {
  if (req->resp_state == _RESP_ENDED) {
    return GRPC_ERROR_STREAM_CLOSED;
  }
  if (req->resp_state == _RESP_END_PENDING) {
    return 0;
  }

  req->grpc_status = _rc2grpc(rc);
  req->error_explained = _percent_encode(req->pool, message);

  if (req->resp_state == _RESP_NONE && !req->mslots) {
    // Trailers-only response: headers with grpc-status and END_STREAM.
    struct iwn_grpc_server *server = req->conn->server;
    struct hive_nv nva[8];
    size_t n = 0;
    char status[16];
    snprintf(status, sizeof(status), "%d", req->grpc_status);

    _hive_nv_set(&nva[n++], ":status", "200", 0);
    _hive_nv_set(&nva[n++], "content-type", "application/grpc+proto", 0);
    _hive_nv_set(&nva[n++], "grpc-accept-encoding", server->spec.grpc.accept_encoding, 0);
    _hive_nv_set(&nva[n++], "grpc-status", status, 0);
    if (req->error_explained) {
      _hive_nv_set(&nva[n++], "grpc-message", req->error_explained, 0);
    }

    iwrc r = _hrc2rc(hive_submit_response(req->conn->sess, req->ctx.stream_id, nva, n, 0));
    if (r) {
      return r;
    }
    req->resp_state = _RESP_ENDED;
    req->src_finished = true;
    return 0;
  }

  if (req->resp_state == _RESP_NONE) {
    rc = _req_write_headers_locked(req, 0);
    if (rc) {
      return rc;
    }
  }
  req->resp_state = _RESP_END_PENDING;
  return 0;
}

static void _req_free(struct _server_req *req) {
  iwref_unref(&req->conn->ref);
  _rx_destroy(&req->rx);
  iwpool_destroy(req->pool);
}

static void _req_destroy(void *d) {
  struct _server_req *req = d;
  struct iwn_grpc_server_spec *spec = &req->conn->server->spec;

  _req_pub_update(req);
#ifdef IW_BLOCKS
  if (spec->on_request_destroy_block) {
    spec->on_request_destroy_block(&req->ctx);
  } else
#endif
  if (spec->on_request_destroy) {
    spec->on_request_destroy(&req->ctx);
  }
  _req_free(req);
}

struct iwn_grpc_server_req* iwn_grpc_server_req_ref(struct iwn_grpc_server_req *req) {
  if (!req || !req->impl) {
    return 0;
  }
  iwref_ref(&((struct _server_req*) req->impl)->ref);
  return req;
}

void iwn_grpc_server_req_unref(struct iwn_grpc_server_req *req) {
  if (!req || !req->impl) {
    return;
  }
  iwref_unref(&((struct _server_req*) req->impl)->ref);
}

static struct _server_req* _req_create(struct iwn_grpc_server_conn *conn, uint32_t stream_id) {
  struct iwpool *pool = iwpool_create_empty();
  if (!pool) {
    return 0;
  }
  struct _server_req *req = iwpool_calloc(sizeof(*req), pool);
  if (!req) {
    iwpool_destroy(pool);
    return 0;
  }
  req->pool = pool;
  req->conn = conn;
  req->ctx.stream_id = stream_id;
  req->ctx.impl = req;
  req->resp_state = _RESP_NONE;
  _rx_init(&req->rx);
  iwref_ref(&conn->ref);
  iwref_init(&req->ref, req, _req_destroy);
  return req;
}

iwrc iwn_grpc_server_req_write_headers(struct iwn_grpc_server_req *req_pub, const char *encoding) {
  if (!req_pub || !req_pub->impl) {
    return IW_ERROR_INVALID_ARGS;
  }
  struct _server_req *req = req_pub->impl;
  struct iwn_grpc_server_conn *conn = req->conn;
  iwrc rc = 0;

  pthread_mutex_lock(&conn->mtx);
  if (conn->pa_closed || !conn->sess || hive_session_closed(conn->sess)) {
    rc = GRPC_ERROR_STREAM_CLOSED;
  } else if (req->resp_state != _RESP_NONE) {
    rc = IW_ERROR_INVALID_STATE;
  } else {
    RCC(rc, finish, _req_write_headers_locked(req, encoding));
  }

finish:
  pthread_mutex_unlock(&conn->mtx);
  if (!rc && !conn->pa_closed && conn->pa) {
    conn->pa->arm(conn->pa, IWN_POLLOUT);
  }
  return rc;
}

iwrc iwn_grpc_server_req_write_message(
  struct iwn_grpc_server_req *req_pub,
  const struct iwn_val       *msg,
  bool                        compressed) {
  if (!req_pub || !req_pub->impl || !msg) {
    return IW_ERROR_INVALID_ARGS;
  }
  struct _server_req *req = req_pub->impl;
  struct iwn_grpc_server_conn *conn = req->conn;
  struct _msg_slot *ns = 0;
  iwrc rc = 0;

  pthread_mutex_lock(&conn->mtx);
  if (conn->pa_closed || !conn->sess || hive_session_closed(conn->sess)) {
    rc = GRPC_ERROR_STREAM_CLOSED;
    goto finish;
  }
  if (req->resp_state == _RESP_ENDED || req->resp_state == _RESP_END_PENDING) {
    rc = GRPC_ERROR_STREAM_CLOSED;
    goto finish;
  }
  RCC(rc, finish, _msg_slot_create(req, msg, compressed, &ns));
  RCC(rc, finish, _req_write_headers_locked(req, 0));

  if (req->mslots) {
    struct _msg_slot *rs = req->mslots;
    while (rs->next) {
      rs = rs->next;
    }
    rs->next = ns;
  } else {
    req->mslots = ns;
  }
  ns = 0;
  // Allow one more send attempt for the newly queued message.
  conn->send_blocked = false;

finish:
  if (ns) {
    _msg_slot_destroy(ns);
  }
  pthread_mutex_unlock(&conn->mtx);
  if (!rc && !conn->pa_closed && conn->pa) {
    conn->pa->arm(conn->pa, IWN_POLLOUT);
  }
  return rc;
}

iwrc iwn_grpc_server_req_end(struct iwn_grpc_server_req *req_pub, iwrc rc, const char *message) {
  if (!req_pub || !req_pub->impl) {
    return IW_ERROR_INVALID_ARGS;
  }
  struct _server_req *req = req_pub->impl;
  struct iwn_grpc_server_conn *conn = req->conn;
  iwrc r = 0;

  pthread_mutex_lock(&conn->mtx);
  if (conn->pa_closed || !conn->sess || hive_session_closed(conn->sess)) {
    r = GRPC_ERROR_STREAM_CLOSED;
  } else {
    RCC(r, finish, _req_end_locked(req, rc, message));
  }

finish:
  pthread_mutex_unlock(&conn->mtx);
  if (!r && !conn->pa_closed && conn->pa) {
    conn->pa->arm(conn->pa, IWN_POLLOUT);
  }
  return r;
}

void iwn_grpc_server_req_cancel(struct iwn_grpc_server_req *req_pub) {
  if (!req_pub || !req_pub->impl) {
    return;
  }
  struct _server_req *req = req_pub->impl;
  struct iwn_grpc_server_conn *conn = req->conn;

  if (!__sync_bool_compare_and_swap(&req->cancel_pending, false, true)) {
    return;
  }

  pthread_mutex_lock(&conn->mtx);
  if (!conn->pa_closed && conn->sess && !hive_session_closed(conn->sess)) {
    // Triggers on_stream_close and the request destruction flow.
    hive_submit_rst_stream(conn->sess, req->ctx.stream_id, HIVE_H2_CANCEL);
  }
  pthread_mutex_unlock(&conn->mtx);

  if (!conn->pa_closed && conn->pa) {
    conn->pa->arm(conn->pa, IWN_POLLOUT);
  }
}

///////////////////////////////////////////////////////////////////////////
//                          Hive session callbacks                         //
///////////////////////////////////////////////////////////////////////////

static int _hcb_on_begin_headers(hive_session_t *session, uint32_t stream_id, void *user_data) {
  struct iwn_grpc_server_conn *conn = user_data;
  if (iwhmap_get_u32(conn->requests_map, stream_id)) {
    // Trailers of an already known request.
    return 0;
  }
  struct _server_req *req = _req_create(conn, stream_id);
  if (!req) {
    return HIVE_ERR_NOMEM;
  }
  iwrc rc = iwhmap_put_u32(conn->requests_map, stream_id, req);
  if (rc) {
    _req_free(req);
    return HIVE_ERR_NOMEM;
  }
  return 0;
}

static int _hcb_on_header(
  hive_session_t *session,
  uint32_t        stream_id,
  hive_buf_t     *nb,
  hive_buf_t     *vb,
  uint8_t         flags,
  void           *user_data) {
  struct iwn_grpc_server_conn *conn = user_data;
  struct _server_req *req = iwhmap_get_u32(conn->requests_map, stream_id);
  if (!req) {
    return HIVE_ERR;
  }
  if (req->headers_done) {
    return 0; // Do not process trailers
  }

  const char **dst = 0;

  if (nb->len == IW_LLEN(":path") && !strncmp((const char*) nb->data, ":path", nb->len)) {
    dst = &req->ctx.path;
  } else if (nb->len == IW_LLEN(":authority") && !strncmp((const char*) nb->data, ":authority", nb->len)) {
    dst = &req->ctx.authority;
  } else if (nb->len == IW_LLEN(":method") && !strncmp((const char*) nb->data, ":method", nb->len)) {
    dst = &req->ctx.method;
  } else if (nb->len == IW_LLEN("content-type") && !strncmp((const char*) nb->data, "content-type", nb->len)) {
    dst = &req->ctx.content_type;
  } else if (nb->len == IW_LLEN("authorization") && !strncmp((const char*) nb->data, "authorization", nb->len)) {
    dst = &req->ctx.authorization;
  } else if (nb->len == IW_LLEN("grpc-encoding") && !strncmp((const char*) nb->data, "grpc-encoding", nb->len)) {
    dst = &req->ctx.data_encoding;
  }

  if (dst) {
    char *v = iwpool_strndup2(req->pool, (const char*) vb->data, vb->len);
    if (!v) {
      return HIVE_ERR_NOMEM;
    }
    *dst = v;
  }
  return 0;
}

static int _hcb_on_headers_complete(
  hive_session_t *session,
  uint32_t        stream_id,
  uint8_t         flags,
  void           *user_data) {
  struct iwn_grpc_server_conn *conn = user_data;
  struct iwn_grpc_server_spec *spec = &conn->server->spec;
  struct _server_req *req = iwhmap_get_u32(conn->requests_map, stream_id);
  if (!req) {
    return HIVE_ERR;
  }
  if (req->headers_done) {
    return 0; // Trailers
  }
  req->headers_done = true;

  iwrc rc = 0;
  if (!req->ctx.method || strcmp(req->ctx.method, "POST") != 0) {
    rc = GRPC_ERROR_INVALID_ARGUMENT;
  } else if (!req->ctx.path || !*req->ctx.path) {
    rc = GRPC_ERROR_UNIMPLEMENTED;
  } else if (!req->ctx.content_type || strncmp(req->ctx.content_type, "application/grpc",
                                               IW_LLEN("application/grpc"))) {
    rc = GRPC_ERROR_INVALID_ARGUMENT;
  } else {
    req->req_started = true;
    _req_pub_update(req);
#ifdef IW_BLOCKS
    if (spec->on_request_block) {
      rc = spec->on_request_block(&req->ctx);
    } else
#endif
    if (spec->on_request) {
      rc = spec->on_request(&req->ctx);
    }
  }

  if (rc) {
    req->rc = rc;
    req->req_started = false;
    iwrc erc = _req_end_locked(req, rc, 0);
    if (erc) {
      iwlog_ecode_error3(erc);
    }
  }
  return 0;
}

static int _hcb_on_data_chunk(
  hive_session_t *session,
  uint32_t        stream_id,
  const uint8_t  *data,
  size_t          len,
  uint8_t         flags,
  void           *user_data) {
  struct iwn_grpc_server_conn *conn = user_data;
  struct iwn_grpc_server_spec *spec = &conn->server->spec;
  struct _server_req *req = iwhmap_get_u32(conn->requests_map, stream_id);
  if (!req) {
    return HIVE_ERR;
  }
  struct _rx *rx = &req->rx;

  if (  !req->req_started || req->rc || rx->state == _RX_STOP
     || req->resp_state == _RESP_ENDED) {
    return 0;
  }

  if (rx->body == 0) {
    rx->body = iwxstr_create_empty();
    if (!rx->body) {
      req->rc = iwrc_set_errno(IW_ERROR_ALLOC, errno);
      return HIVE_ERR_NOMEM;
    }
  }

  size_t off = 0;
  while (off < len) {
    // HEADER
    if (rx->state == _RX_HEADER) {
      size_t need = 5 - rx->header_len;
      size_t take = need < (len - off) ? need : (len - off);
      memcpy(rx->header + rx->header_len, data + off, take);
      rx->header_len += take;
      off += take;
      if (rx->header_len < 5) {
        continue;
      }
      if (rx->header[0] > 1) {
        req->rc = GRPC_ERROR_H2_PROTOCOL;
        return HIVE_ERR_PROTOCOL;
      }
      rx->compressed = rx->header[0];
      memcpy(&rx->body_len, &rx->header[1], sizeof(uint32_t));
#ifndef IW_BIGENDIAN
      rx->body_len = IW_SWAB32(rx->body_len);
#endif
      if (rx->body_len > conn->server->spec.grpc.max_message_bytes) {
        req->rc = GRPC_ERROR_MSG_TOO_LARGE;
        return HIVE_ERR;
      }
      iwxstr_clear(rx->body);
      rx->state = _RX_BODY;
    }

    // BODY
    if (rx->state == _RX_BODY) {
      size_t need = rx->body_len - iwxstr_size(rx->body);
      size_t take = need < (len - off) ? need : (len - off);

      if (take > 0) {
        iwxstr_cat(rx->body, data + off, take);
        off += take;
      }

      if (iwxstr_size(rx->body) < rx->body_len) {
        continue;
      }

      { // Call on_message() callback
        struct iwn_grpc_server_msg msg = {
          .req = &req->ctx,
          .msg = {
            .buf = iwxstr_ptr(rx->body),
            .len = rx->body_len,
          },
          .compressed = rx->compressed
        };
        _req_pub_update(req);
        msg.req = &req->ctx;
        bool keep_going = true;

#ifdef IW_BLOCKS
        if (spec->on_message_block) {
          spec->on_message_block(&msg, &keep_going);
        } else
#endif
        if (spec->on_message) {
          spec->on_message(&msg, &keep_going);
        }

        _rx_reset(rx);
        if (!keep_going) {
          rx->state = _RX_STOP;
          break;
        } else {
          rx->state = _RX_HEADER;
        }
      }
    }
  }

  return req->rc ? HIVE_ERR : 0;
}

static iwrc _on_stream_close_deferred(const struct _deferred_callback *cb) {
  struct iwn_grpc_server_conn *conn = cb->conn;
  struct iwn_grpc_server_spec *spec = &conn->server->spec;
  struct _server_req *req;

  pthread_mutex_lock(&conn->mtx);
  req = iwhmap_get_u32(conn->requests_map, cb->stream_id);
  if (req) {
    iwref_ref(&req->ref);
  }
  pthread_mutex_unlock(&conn->mtx);
  if (!req) {
    return 0;
  }

  if (cb->error_code && !req->rc) {
    req->rc = _hrc2rc(cb->error_code);
  }
  _req_pub_update(req);

#ifdef IW_BLOCKS
  if (spec->on_request_closed_block) {
    spec->on_request_closed_block(&req->ctx);
  } else
#endif
  if (spec->on_request_closed) {
    spec->on_request_closed(&req->ctx);
  }

  pthread_mutex_lock(&conn->mtx);
  iwhmap_remove_u32(conn->requests_map, cb->stream_id);
  pthread_mutex_unlock(&conn->mtx);

  iwref_unref(&req->ref); // map ref
  iwref_unref(&req->ref); // lookup ref
  return 0;
}

static int _hcb_on_stream_close(
  hive_session_t *session,
  uint32_t        stream_id,
  uint32_t        error_code,
  void           *user_data) {
  return _conn_deferred_register(user_data, &(struct _deferred_callback) {
    .conn = user_data,
    .execute = _on_stream_close_deferred,
    .error_code = error_code,
    .stream_id = stream_id,
  }) ? 0 : HIVE_ERR_NOMEM;
}

static iwrc _on_conn_error_deferred(const struct _deferred_callback *cb) {
  struct iwn_grpc_server_conn *conn = cb->conn;
  struct iwn_grpc_server_spec *spec = &conn->server->spec;
  if (conn->error_reported) {
    return 0;
  }
  conn->error_reported = true;

  struct iwn_grpc_server_conn_ctx ctx;
  _conn_ctx_init(conn, &ctx);
#ifdef IW_BLOCKS
  if (spec->on_error_block) {
    spec->on_error_block(&ctx);
  } else
#endif
  if (spec->on_error) {
    spec->on_error(&ctx);
  }
  return 0;
}

static int _hcb_on_connection_error(
  hive_session_t *session,
  int             hive_err,
  uint32_t        h2_error_code,
  void           *user_data) {
  struct iwn_grpc_server_conn *conn = user_data;
  if (!conn->rc) {
    conn->rc = _hrc2rc(hive_err ? hive_err : h2_error_code);
    _conn_deferred_register(conn, &(struct _deferred_callback) {
      .conn = conn,
      .execute = _on_conn_error_deferred,
      .error_code = conn->rc,
    });
  }
  return 0;
}

static int _hcb_on_goaway(
  hive_session_t *session,
  uint32_t        last_stream_id,
  uint32_t        error_code,
  const uint8_t  *debug_data,
  size_t          debug_len,
  void           *user_data) {
  struct iwn_grpc_server_conn *conn = user_data;
  if (error_code && !conn->rc) {
    conn->rc = _hrc2rc(error_code);
    _conn_deferred_register(conn, &(struct _deferred_callback) {
      .conn = conn,
      .execute = _on_conn_error_deferred,
      .error_code = conn->rc,
    });
  }
  __sync_bool_compare_and_swap(&conn->goaway_submitted, false, true);
  return 0;
}

///////////////////////////////////////////////////////////////////////////
//                              Connection                                 //
///////////////////////////////////////////////////////////////////////////

static bool _conn_want_write(struct iwn_grpc_server_conn *conn) {
  // Queued wire output (DATA/HEADERS/RST/GOAWAY and partial writes)
  // must always be flushed.
  if (hive_session_want_write(conn->sess, 1)) {
    return true;
  }
  if (conn->send_blocked) {
    // Remaining response messages wait for a WINDOW_UPDATE/SETTINGS frame.
    return false;
  }
  struct iwhmap_iter it;
  iwhmap_iter_init(conn->requests_map, &it);
  while (iwhmap_iter_next(&it)) {
    const struct _server_req *req = it.val;
    if (req->mslots) {
      return true;
    }
  }
  return false;
}

/// Runs a bounded number of send rounds.
/// Stops early when a round produces no frames and no framed output is left:
/// the remaining response data sources are blocked by the HTTP/2 flow-control
/// window. This avoids busy spinning both inside this callback and in the
/// poller when write interest would otherwise be rearmed.
static int _conn_send_rounds(struct iwn_grpc_server_conn *conn) {
  int hrc = HIVE_OK;

  for (int rounds = 0; rounds < 512 && hrc == HIVE_OK && !conn->io_wouldblock; ++rounds) {
    if (!_conn_want_write(conn)) {
      break;
    }

    conn->io_progress = false;
    hrc = hive_session_send(conn->sess);

    if (hrc != HIVE_OK || conn->io_progress || conn->io_wouldblock) {
      continue;
    }

    // No frames were emitted. If nothing is queued for the wire either,
    // the data sources are blocked by the peer flow-control window.
    if (!hive_session_want_write(conn->sess, 1)) {
      conn->send_blocked = true;
    }
    break;
  }

  return hrc;
}

static bool _conn_has_pending_end(struct iwn_grpc_server_conn *conn) {
  struct iwhmap_iter it;
  iwhmap_iter_init(conn->requests_map, &it);
  while (iwhmap_iter_next(&it)) {
    const struct _server_req *req = it.val;
    if (req->resp_state == _RESP_END_PENDING && !req->src_finished) {
      return true;
    }
  }
  return false;
}

/// Gives response data sources a chance to detach after all queued messages are
/// sent. This is required before trailers can be submitted. The loop stops when
/// no data source is pending or when the peer flow-control window blocks further
/// progress.
static iwrc _conn_drive_pending_ends(struct iwn_grpc_server_conn *conn) {
  for (int rounds = 0; rounds < 512; ++rounds) {
    if (!_conn_has_pending_end(conn)) {
      break;
    }

    conn->io_progress = false;
    int hrc = hive_session_send(conn->sess);
    if (!_hive_rc_is_ok_for_io(hrc)) {
      return _hrc2rc(hrc);
    }

    if (!_conn_has_pending_end(conn)) {
      // The data source detached, trailers can be submitted.
      break;
    }

    if (!conn->io_progress) {
      if (!hive_session_want_write(conn->sess, 1)) {
        // Blocked by the peer flow-control window.
        conn->send_blocked = true;
      }
      break;
    }
  }
  return 0;
}

static void _conn_update_remote_ends(struct iwn_grpc_server_conn *conn) {
  struct iwn_grpc_server_spec *spec = &conn->server->spec;
  struct iwhmap_iter it;
  iwhmap_iter_init(conn->requests_map, &it);
  while (iwhmap_iter_next(&it)) {
    struct _server_req *req = (struct _server_req*) it.val;
    if (!req->req_started || req->remote_end) {
      continue;
    }
    hive_stream_state_t st = hive_stream_get_state(conn->sess, req->ctx.stream_id);
    if (st == HIVE_STREAM_HALF_CLOSED_REMOTE || st == HIVE_STREAM_CLOSED) {
      req->remote_end = true;
      _req_pub_update(req);
#ifdef IW_BLOCKS
      if (spec->on_request_end_block) {
        spec->on_request_end_block(&req->ctx);
      } else
#endif
      if (spec->on_request_end) {
        spec->on_request_end(&req->ctx);
      }
    }
  }
}

static void _conn_flush_pending_ends(struct iwn_grpc_server_conn *conn) {
  struct iwhmap_iter it;
  iwhmap_iter_init(conn->requests_map, &it);
  while (iwhmap_iter_next(&it)) {
    struct _server_req *req = (struct _server_req*) it.val;
    if (req->resp_state == _RESP_END_PENDING && req->src_finished) {
      // Marks the request as ended regardless of the result.
      (void) _req_submit_trailers_locked(req);
    }
  }
}

static int64_t _conn_on_event_impl(struct iwn_poller_adapter *pa, void *user_data, uint32_t events) {
  struct iwn_grpc_server_conn *conn = user_data;
  if (IW_UNLIKELY(conn->pa != pa)) {
    conn->pa = pa;
  }

  iwrc rc = 0;
  int64_t ret = 0;
  int hrc = HIVE_OK;
  bool input_consumed = false;
  uint8_t buf[8192];
  struct hive_session *sess = conn->sess;

  pthread_mutex_lock(&conn->mtx);

  if (IW_UNLIKELY(hive_session_closed(sess))) {
    pthread_mutex_unlock(&conn->mtx);
    return -1;
  }

  conn->in_loop = true;
  conn->io_wouldblock = false;

  hrc = _conn_send_rounds(conn);
  if (!_hive_rc_is_ok_for_io(hrc)) {
    goto unlock;
  }

  // Process input previously buffered due to the outbound queue pressure.
  while (iwxstr_len(conn->input_buf) && hive_session_want_read(sess)) {
    size_t blen = iwxstr_len(conn->input_buf);
    uint8_t *p = (void*) iwxstr_ptr(conn->input_buf);
    ssize_t consumed = hive_session_recv(sess, p, blen);
    if (consumed < 0) {
      ret = -1;
      hrc = hive_session_last_error(sess);
      goto unlock;
    }
    if (consumed > 0) {
      input_consumed = true;
    }
    iwxstr_shift(conn->input_buf, consumed);
    if ((size_t) consumed < blen) {
      break;
    }
  }

  // Drain the socket while it is readable (edge triggered poller).
  while (!iwxstr_len(conn->input_buf) && hive_session_want_read(sess)) {
    ssize_t n = pa->read(pa, buf, sizeof(buf));
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      } else if (errno == EWOULDBLOCK || errno == EAGAIN) {
        conn->io_wouldblock = true;
        break;
      } else {
        rc = iwrc_set_errno(IW_ERROR_IO_ERRNO, errno);
        ret = -1;
        goto unlock;
      }
    } else if (n == 0) {
      if (!conn->rc) {
        conn->rc = GRPC_ERROR_UNAVAILABLE;
      }
      ret = -1;
      break;
    }
    ssize_t consumed = hive_session_recv(sess, buf, n);
    if (consumed < 0) {
      ret = -1;
      hrc = hive_session_last_error(sess);
      goto unlock;
    }
    if (consumed > 0) {
      input_consumed = true;
    }
    if (consumed < n) {
      RCC(rc, unlock, iwxstr_cat(conn->input_buf, buf + consumed, n - consumed));
      break;
    }
  }

  if (conn->send_blocked && input_consumed) {
    // The peer may have sent WINDOW_UPDATE/SETTINGS that unblock response data.
    conn->send_blocked = false;
    hrc = _conn_send_rounds(conn);
    if (!_hive_rc_is_ok_for_io(hrc)) {
      goto unlock;
    }
  }

  _conn_update_remote_ends(conn);
  RCC(rc, unlock, _conn_drive_pending_ends(conn));
  _conn_flush_pending_ends(conn);

  if (hive_session_want_read(sess)) {
    ret |= IWN_POLLIN;
  }
  if (_conn_want_write(conn)) {
    ret |= IWN_POLLOUT;
  } else if (conn->goaway_submitted && !pa->has_pending_write_bytes(pa)) {
    // Nothing to write, so we may close the socket fd
    ret = -1;
  }

unlock:
  conn->in_loop = false;
  pthread_mutex_unlock(&conn->mtx);

  if (!rc && !_hive_rc_is_ok_for_io(hrc)) {
    rc = _hrc2rc(hrc);
  }

  if (rc) {
    if (ret != -1) {
      ret = -1;
    }
    if (!conn->rc) {
      conn->rc = rc;
      _conn_deferred_register(conn, &(struct _deferred_callback) {
        .conn = conn,
        .execute = _on_conn_error_deferred,
        .error_code = rc,
      });
    }
    if (!(conn->server->spec.flags & IWN_GRPC_LOG_QUIET)) {
      iwlog_ecode_error3(rc);
    }
  }

  return ret;
}

static int64_t _conn_on_event(struct iwn_poller_adapter *pa, void *user_data, uint32_t events) {
  struct iwn_grpc_server_conn *conn = user_data;
  int64_t ret = _conn_on_event_impl(pa, user_data, events);
  iwrc rc = _conn_deferred_execute(conn);
  if (rc) {
    ret = -1;
  }
  return ret;
}

static void _conn_on_dispose(struct iwn_poller_adapter *pa, void *user_data) {
  struct iwn_grpc_server_conn *conn = user_data;
  struct iwn_grpc_server_spec *spec = &conn->server->spec;

  conn->pa_closed = true;

  struct iwulist rlist = { .usize = sizeof(struct _server_req*) };
  pthread_mutex_lock(&conn->mtx);

  struct iwhmap_iter it;
  iwhmap_iter_init(conn->requests_map, &it);
  while (iwhmap_iter_next(&it)) {
    struct _server_req *req = (struct _server_req*) it.val;
    iwref_ref(&req->ref);
    iwulist_push(&rlist, &req);
  }
  iwhmap_clear(conn->requests_map);
  pthread_mutex_unlock(&conn->mtx);

  for (size_t i = 0; i < rlist.num; ++i) {
    struct _server_req *req = *(struct _server_req**) iwulist_get(&rlist, i);
    if (!req->rc) {
      req->rc = conn->rc ? conn->rc : GRPC_ERROR_UNAVAILABLE;
    }
    _req_pub_update(req);
#ifdef IW_BLOCKS
    if (spec->on_request_closed_block) {
      spec->on_request_closed_block(&req->ctx);
    } else
#endif
    if (spec->on_request_closed) {
      spec->on_request_closed(&req->ctx);
    }
  }

  for (size_t i = 0; i < rlist.num; ++i) {
    struct _server_req *req = *(struct _server_req**) iwulist_get(&rlist, i);
    iwref_unref(&req->ref); // lookup ref
    iwref_unref(&req->ref); // map ref
  }
  iwulist_destroy_keep(&rlist);

  struct iwn_grpc_server_conn_ctx ctx;
  _conn_ctx_init(conn, &ctx);
#ifdef IW_BLOCKS
  if (spec->on_closed_block) {
    spec->on_closed_block(&ctx);
  } else
#endif
  if (spec->on_closed) {
    spec->on_closed(&ctx);
  }

  conn->pa = 0;

  pthread_mutex_lock(&conn->server->mtx);
  iwhmap_remove_u32(conn->server->conns_map, conn->fd);
  pthread_mutex_unlock(&conn->server->mtx);
  iwref_unref(&conn->ref); // server map ref

  iwref_unref(&conn->ref); // poller adapter ref
}

static void _conn_destroy(void *d) {
  struct iwn_grpc_server_conn *conn = d;

  iwulist_destroy_keep(&conn->deferred_callbacks);
  iwhmap_destroy(conn->requests_map);
  iwxstr_destroy(conn->input_buf);
  pthread_mutex_destroy(&conn->mtx);

  if (conn->sess) {
    hive_session_free(conn->sess);
  }
  if (conn->hive_options) {
    hive_options_free(conn->hive_options);
  }

  iwref_unref(&conn->server->ref);
  iwpool_destroy(conn->pool);
}

static iwrc _conn_hive_pre_init(struct iwn_grpc_server_conn *conn) {
  iwrc rc = 0;
  struct hive_callbacks *cbs = &conn->hive_callbacks;

  memset(cbs, 0, sizeof(*cbs));
  cbs->on_begin_headers = _hcb_on_begin_headers;
  cbs->on_header = _hcb_on_header;
  cbs->on_headers_complete = _hcb_on_headers_complete;
  cbs->on_connection_error = _hcb_on_connection_error;
  cbs->on_goaway = _hcb_on_goaway;
  cbs->on_stream_close = _hcb_on_stream_close;
  cbs->send = _hcb_io_send;
  cbs->on_data_chunk = _hcb_on_data_chunk;

  if (conn->hive_options) {
    hive_options_free(conn->hive_options);
  }

  RCB(finish, conn->hive_options = hive_options_new());

  uint32_t max_streams = conn->server->spec.grpc.max_concurrent_streams;
  if (max_streams && hive_options_set_max_concurrent_streams(conn->hive_options, max_streams) != HIVE_OK) {
    rc = GRPC_ERROR_CONFIG;
    iwlog_ecode_error3(rc);
    goto finish;
  }

finish:
  return rc;
}

static iwrc _conn_start(struct iwn_grpc_server_conn *conn) {
  iwrc rc = 0;
  struct iwn_grpc_server *server = conn->server;

  RCC(rc, finish, _conn_hive_pre_init(conn));

  conn->sess = hive_session_server_new(0, conn->hive_options, &conn->hive_callbacks, conn);
  if (!conn->sess) {
    rc = GRPC_ERROR;
    iwlog_ecode_error2(rc, "grpc | Hive session initialization failed");
    goto finish;
  }

  if (conn->flags & _FLAG_SECURE) {
    rc = iwn_brssl_server_poller_adapter(&(struct iwn_brssl_server_poller_adapter_spec) {
      .poller = server->poller,
      .alpn_protocol_names = "h2", //< Only HTTP/2 is supported and allowed
      .on_event = _conn_on_event,
      .on_dispose = _conn_on_dispose,
      .user_data = conn,
      .timeout_sec = server->spec.inactivity_timeout_sec,
      .events = IWN_POLLIN,
      .events_mod = IWN_POLLET,
      .fd = conn->fd,
      .certs = server->spec.ssl.certs,
      .certs_len = server->spec.ssl.certs_len,
      .certs_in_buffer = server->spec.ssl.certs_in_buffer,
      .private_key = server->spec.ssl.private_key,
      .private_key_len = server->spec.ssl.private_key_len,
      .private_key_in_buffer = server->spec.ssl.private_key_in_buffer,
    });
  } else {
    rc = iwn_direct_poller_adapter(
      server->poller, conn->fd,
      _conn_on_event,
      _conn_on_dispose,
      conn, IWN_POLLIN, IWN_POLLET,
      server->spec.inactivity_timeout_sec);
  }

finish:
  return rc;
}

static iwrc _conn_create(struct iwn_grpc_server *server, int fd, struct iwn_grpc_server_conn **out) {
  iwrc rc = 0;
  *out = 0;

  struct iwpool *pool = iwpool_create_empty();
  if (!pool) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  struct iwn_grpc_server_conn *conn = iwpool_calloc(sizeof(*conn), pool);
  if (!conn) {
    iwpool_destroy(pool);
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  conn->pool = pool;
  conn->server = server;
  conn->fd = fd;
  conn->flags = server->flags;

  pthread_mutexattr_t attr;
  pthread_mutexattr_init(&attr);
  pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
  pthread_mutex_init(&conn->mtx, &attr);
  pthread_mutexattr_destroy(&attr);

  conn->input_buf = iwxstr_create_empty();
  conn->requests_map = iwhmap_create_u32(0);
  if (!conn->input_buf || !conn->requests_map) {
    rc = iwrc_set_errno(IW_ERROR_ALLOC, errno);
    goto fail_early;
  }
  RCC(rc, fail_early, iwulist_init(&conn->deferred_callbacks, 8, sizeof(struct _deferred_callback)));

  iwref_ref(&server->ref);
  iwref_init(&conn->ref, conn, _conn_destroy);

  pthread_mutex_lock(&server->mtx);
  rc = iwhmap_put_u32(server->conns_map, fd, conn);
  pthread_mutex_unlock(&server->mtx);
  if (rc) {
    iwref_unref(&conn->ref);
    return rc;
  }
  iwref_ref(&conn->ref); // server map ref

  rc = _conn_start(conn);
  if (rc) {
    pthread_mutex_lock(&server->mtx);
    iwhmap_remove_u32(server->conns_map, fd);
    pthread_mutex_unlock(&server->mtx);
    iwref_unref(&conn->ref); // server map ref
    iwref_unref(&conn->ref); // initial ref (poller adapter was not created)
    return rc;
  }

  *out = conn;
  return 0;

fail_early:
  iwxstr_destroy(conn->input_buf);
  iwhmap_destroy(conn->requests_map);
  pthread_mutex_destroy(&conn->mtx);
  iwpool_destroy(pool);
  return rc;
}

///////////////////////////////////////////////////////////////////////////
//                                Server                                   //
///////////////////////////////////////////////////////////////////////////

static void _server_destroy(void *d) {
  struct iwn_grpc_server *server = d;
  struct iwn_grpc_server_spec *spec = &server->spec;

  if (server->opened) {
    struct iwn_grpc_server_ctx ctx = {
      .rc = 0,
      .server = server,
      .user_data = spec->user_data,
    };
#ifdef IW_BLOCKS
    if (spec->on_destroy_block) {
      spec->on_destroy_block(&ctx);
    } else
#endif
    if (spec->on_destroy) {
      spec->on_destroy(&ctx);
    }
  }

  iwhmap_destroy(server->conns_map);
  pthread_mutex_destroy(&server->mtx);

#ifdef IW_BLOCKS
  Block_release(spec->on_request_block);
  Block_release(spec->on_message_block);
  Block_release(spec->on_request_end_block);
  Block_release(spec->on_request_closed_block);
  Block_release(spec->on_request_destroy_block);
  Block_release(spec->on_closed_block);
  Block_release(spec->on_error_block);
  Block_release(spec->on_destroy_block);
#endif

  iwpool_destroy(server->pool);
}

static int64_t _server_on_ready(const struct iwn_poller_task *t, uint32_t events) {
  struct iwn_grpc_server *server = t->user_data;

  while (!server->closed_by_api) {
    struct sockaddr_storage sockaddr = { 0 };
    socklen_t sockaddr_len = sizeof(sockaddr);

    int fd = accept(t->fd, (struct sockaddr*) &sockaddr, &sockaddr_len);
    if (fd < 0) {
      if (errno == EINTR) {
        continue;
      }
      if (!(errno == EWOULDBLOCK || errno == EAGAIN)) {
        if (!(server->spec.flags & IWN_GRPC_LOG_QUIET)) {
          iwlog_warn("grpc | Server accept failed: %s", strerror(errno));
        }
      }
      break;
    }

    fcntl(fd, F_SETFD, FD_CLOEXEC);

    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
      close(fd);
      continue;
    }

    struct iwn_grpc_server_conn *conn = 0;
    iwrc rc = _conn_create(server, fd, &conn);
    if (rc) {
      close(fd);
      if (!(server->spec.flags & IWN_GRPC_LOG_QUIET)) {
        iwlog_ecode_error(rc, "grpc | Failed to create server connection fd: %d", fd);
      }
    }
  }

  return 0;
}

static void _server_on_dispose(const struct iwn_poller_task *t) {
  struct iwn_grpc_server *server = t->user_data;
  iwref_unref(&server->ref);
}

static iwrc _listen_url_prepare(struct iwn_grpc_server *server) {
  iwrc rc = 0;
  struct iwn_grpc_server_spec *spec = &server->spec;

  char *ubuf = iwpool_strdup2(server->pool, spec->url);
  RCB(finish, ubuf);

  if (iwn_url_parse(&server->url, ubuf) == -1) {
    iwlog_error("grpc | Failed to parse url: %s", spec->url);
    rc = IW_ERROR_INVALID_ARGS;
    goto finish;
  }

  if (server->url.scheme) {
    if (strcmp("grpc+plaintext", server->url.scheme) == 0) {
      ;
    } else if (strcmp("grpc+socket", server->url.scheme) == 0) {
      server->flags |= _FLAG_NO_NETWORK;
      if (server->url.host == server->url.path - 1) {
        *(server->url.path - 1) = '/'; // WARNING: Dependent on iwn_url_parse implementation
      }
    } else {
      server->flags |= _FLAG_SECURE;
    }
  }

  if (server->url.port < 1) {
    server->url.port = 50051;
  }

  if (server->flags & _FLAG_SECURE) {
    if (!spec->ssl.certs || !spec->ssl.private_key || spec->ssl.certs_len < 1 || spec->ssl.private_key_len < 1) {
      rc = GRPC_ERROR_CONFIG;
      iwlog_ecode_error2(rc, "TLS certificates are required for the secure gRPC server url");
      goto finish;
    }
  }

finish:
  return rc;
}

static iwrc _listen_socket_open(struct iwn_grpc_server *server) {
  iwrc rc = 0;
  int fd = -1;
  int optval = 1;
  struct iwn_grpc_server_spec *spec = &server->spec;

  struct iwn_poller_task task = {
    .user_data = server,
    .on_ready = _server_on_ready,
    .on_dispose = _server_on_dispose,
    .events = IWN_POLLIN,
    .events_mod = IWN_POLLET,
    .poller = spec->poller,
    .fd = -1,
  };

  if (server->flags & _FLAG_NO_NETWORK) {
    struct sockaddr_un saddr = {
      .sun_family = AF_UNIX,
    };
    size_t listensz = strlen(server->url.host);

    if (listensz >= sizeof(saddr.sun_path)) {
      rc = IW_ERROR_INVALID_ARGS;
      iwlog_ecode_error(rc, "grpc | Unix socket path exceeds its maximum length: %zd", sizeof(saddr.sun_path) - 1);
      goto finish;
    }
    memcpy(saddr.sun_path, server->url.host, listensz + 1);

    unlink(saddr.sun_path);
    RCN(finish, fd = socket(AF_UNIX, SOCK_STREAM, 0));
    RCN(finish, bind(fd, (void*) &saddr, sizeof(saddr)));
  } else {
    struct addrinfo hints = {
      .ai_socktype = SOCK_STREAM,
      .ai_family = AF_UNSPEC,
      .ai_flags = AI_PASSIVE,
    };
    struct addrinfo *result = 0, *rp = 0;
    char port[32];
    snprintf(port, sizeof(port), "%d", server->url.port);

    int rci = getaddrinfo(server->url.host, port, &hints, &result);
    if (rci) {
      rc = GRPC_ERROR_CONFIG;
      iwlog_ecode_error(rc, "grpc | Error getting listen address %s:%s: %s",
                        server->url.host, port, gai_strerror(rci));
      goto finish;
    }

    for (rp = result; rp; rp = rp->ai_next) {
      fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
      if (fd < 0) {
        continue;
      }
      fcntl(fd, F_SETFD, FD_CLOEXEC);
      setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
      if (bind(fd, rp->ai_addr, rp->ai_addrlen) == 0) {
        break;
      }
      close(fd);
      fd = -1;
    }
    freeaddrinfo(result);

    if (fd < 0) {
      rc = iwrc_set_errno(IW_ERROR_ERRNO, errno);
      iwlog_ecode_error2(rc, "Could not find any suitable address to bind");
      goto finish;
    }
  }

  RCN(finish, optval = fcntl(fd, F_GETFL, 0));
  RCN(finish, fcntl(fd, F_SETFL, optval | O_NONBLOCK));

  if (listen(fd, 64) == -1) {
    rc = iwrc_set_errno(IW_ERROR_ERRNO, errno);
    goto finish;
  }

  task.fd = fd;
  iwref_ref(&server->ref); // Will unref in _server_on_dispose

  rc = iwn_poller_add(&task);
  if (rc) {
    iwref_unref(&server->ref);
    goto finish;
  }

  server->listen_fd = fd;

finish:
  if (rc) {
    if (fd > -1) {
      close(fd);
    }
  }
  return rc;
}

iwrc iwn_grpc_server_open(const struct iwn_grpc_server_spec *spec_, struct iwn_grpc_server **out_server) {
  iwrc rc = 0;
  if (!spec_ || !out_server || !spec_->poller || !spec_->url) {
    return IW_ERROR_INVALID_ARGS;
  }
  *out_server = 0;

  rc = iwn_grpc_init();
  RCRET(rc);

  struct iwpool *pool = iwpool_create_empty();
  RCRA(pool);

  struct iwn_grpc_server *server = iwpool_calloc(sizeof(*server), pool);
  if (!server) {
    iwpool_destroy(pool);
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  server->pool = pool;
  server->poller = spec_->poller;
  server->flags = spec_->flags;
  server->listen_fd = -1;
  server->spec = *spec_;

  pthread_mutexattr_t attr;
  pthread_mutexattr_init(&attr);
  pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
  pthread_mutex_init(&server->mtx, &attr);
  pthread_mutexattr_destroy(&attr);

#ifdef IW_BLOCKS
  server->spec.on_request_block = 0;
  server->spec.on_message_block = 0;
  server->spec.on_request_end_block = 0;
  server->spec.on_request_closed_block = 0;
  server->spec.on_request_destroy_block = 0;
  server->spec.on_closed_block = 0;
  server->spec.on_error_block = 0;
  server->spec.on_destroy_block = 0;
#endif

  if (!server->spec.grpc.max_message_bytes) {
    server->spec.grpc.max_message_bytes = 1024 * 1024; // 1Mb
  }
  if (!server->spec.grpc.max_concurrent_streams) {
    server->spec.grpc.max_concurrent_streams = 256;
  }
  if (!server->spec.grpc.accept_encoding) {
    server->spec.grpc.accept_encoding = "identity";
  } else {
    RCB(finish, server->spec.grpc.accept_encoding = iwpool_strdup2(pool, server->spec.grpc.accept_encoding));
  }

  RCB(finish, server->conns_map = iwhmap_create_u32(0));

  // Initial reference is owned by the API caller and released by iwn_grpc_server_close().
  iwref_init(&server->ref, server, _server_destroy);

  RCB(finish, server->spec.url = iwpool_strdup2(pool, server->spec.url));

  server->spec.ssl.certs_len = spec_->ssl.certs_len;
  server->spec.ssl.private_key_len = spec_->ssl.private_key_len;
  if (spec_->ssl.certs) {
    ssize_t len = spec_->ssl.certs_len;
    if (len < 0) {
      len = strlen(spec_->ssl.certs);
    }
    RCB(finish, server->spec.ssl.certs = iwpool_strndup2(pool, spec_->ssl.certs, len));
    server->spec.ssl.certs_len = len;
  }
  if (spec_->ssl.private_key) {
    ssize_t len = spec_->ssl.private_key_len;
    if (len < 0) {
      len = strlen(spec_->ssl.private_key);
    }
    RCB(finish, server->spec.ssl.private_key = iwpool_strndup2(pool, spec_->ssl.private_key, len));
    server->spec.ssl.private_key_len = len;
  }

#ifdef IW_BLOCKS
  if (spec_->on_request_block) {
    RCB(finish, server->spec.on_request_block = Block_copy(spec_->on_request_block));
  }
  if (spec_->on_message_block) {
    RCB(finish, server->spec.on_message_block = Block_copy(spec_->on_message_block));
  }
  if (spec_->on_request_end_block) {
    RCB(finish, server->spec.on_request_end_block = Block_copy(spec_->on_request_end_block));
  }
  if (spec_->on_request_closed_block) {
    RCB(finish, server->spec.on_request_closed_block = Block_copy(spec_->on_request_closed_block));
  }
  if (spec_->on_request_destroy_block) {
    RCB(finish, server->spec.on_request_destroy_block = Block_copy(spec_->on_request_destroy_block));
  }
  if (spec_->on_closed_block) {
    RCB(finish, server->spec.on_closed_block = Block_copy(spec_->on_closed_block));
  }
  if (spec_->on_error_block) {
    RCB(finish, server->spec.on_error_block = Block_copy(spec_->on_error_block));
  }
  if (spec_->on_destroy_block) {
    RCB(finish, server->spec.on_destroy_block = Block_copy(spec_->on_destroy_block));
  }
#endif

  RCC(rc, finish, _listen_url_prepare(server));
  RCC(rc, finish, _listen_socket_open(server));

finish:
  if (rc) {
    server->opened = false;
    _server_destroy(server);
  } else {
    server->opened = true;
    *out_server = server;
  }
  return rc;
}

bool iwn_grpc_server_close(struct iwn_grpc_server *server) {
  if (!server) {
    return false;
  }
  if (!__sync_bool_compare_and_swap(&server->closed_by_api, false, true)) {
    return false;
  }

  if (server->listen_fd > -1) {
    int fd = server->listen_fd;
    server->listen_fd = -1;
    iwn_poller_remove(server->poller, fd);
  }

  struct iwulist clist = { .usize = sizeof(struct iwn_grpc_server_conn*) };
  pthread_mutex_lock(&server->mtx);
  struct iwhmap_iter it;
  iwhmap_iter_init(server->conns_map, &it);
  while (iwhmap_iter_next(&it)) {
    struct iwn_grpc_server_conn *conn = (struct iwn_grpc_server_conn*) it.val;
    iwref_ref(&conn->ref);
    if (iwulist_push(&clist, &conn)) {
      iwref_unref(&conn->ref);
    }
  }
  pthread_mutex_unlock(&server->mtx);

  for (size_t i = 0; i < clist.num; ++i) {
    struct iwn_grpc_server_conn *conn = *(struct iwn_grpc_server_conn**) iwulist_get(&clist, i);
    pthread_mutex_lock(&conn->mtx);
    if (  !conn->pa_closed && conn->sess && !hive_session_closed(conn->sess)
       && __sync_bool_compare_and_swap(&conn->goaway_submitted, false, true)) {
      hive_submit_goaway_final(conn->sess, HIVE_H2_NO_ERROR, 0, 0);
      if (conn->pa) {
        conn->pa->arm(conn->pa, IWN_POLLOUT);
      }
    }
    pthread_mutex_unlock(&conn->mtx);
    iwref_unref(&conn->ref);
  }
  iwulist_destroy_keep(&clist);

  iwref_unref(&server->ref);
  return true;
}

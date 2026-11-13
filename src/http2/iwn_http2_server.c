/*
 * HTTP/2 server transport based on libhive.
 *
 * The HTTP/1 server hands a connection over to this module by calling
 * iwn_http2_conn_attach_alpn() or iwn_http2_conn_attach_preface(). From that
 * moment the poller adapter events are delivered to _conn_on_event() and the
 * HTTP/1 connection object acts only as a connection anchor.
 *
 * Every HTTP/2 stream gets its own struct iwn_http_req with the HTTP/2
 * operations table installed (struct iwn_http_req::impl), so application code
 * (and the iwn_wf web framework) is transport agnostic.
 */

#include "iwn_http2_server.h"
#include "iwn_http_server_internal.h"
#include "iwn_poller.h"

#include <hive.h>

#include <iowow/iwarr.h>
#include <iowow/iwhmap.h>
#include <iowow/iwlog.h>
#include <iowow/iwpool.h>
#include <iowow/iwxstr.h>

#include <ctype.h>
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#define H2_MAX_CHUNK_ITER  64
#define H2_MAX_SEND_ROUNDS 512U

// Request flags
#define H2_REQ_STREAMED        0x01U ///< Request body delivered by chunks.
#define H2_REQ_HAS_CONTENT_LEN 0x02U ///< Request has content-length header.
#define H2_REQ_CHUNKED_RESP    0x04U ///< Chunked (streamed by chunks) response.
#define H2_REQ_STREAM_RESP     0x08U ///< Streamed response.
#define H2_REQ_BAD             0x10U ///< Malformed request.

// Pending event types
#define H2_EV_START 1 ///< Request headers are complete.
#define H2_EV_DATA  2 ///< New request body data available.
#define H2_EV_END   3 ///< Remote side of the stream is closed.

struct h2_conn;

struct h2_event {
  struct h2_req *req;
  int type;
};

struct h2_req {
  struct iwn_http_req pub;
  struct h2_conn     *conn;
  struct iwpool      *pool;
  struct iwn_pairs    headers;      ///< Request headers.
  struct iwn_pairs    resp_headers; ///< Response headers.
  struct iwxstr      *in;           ///< Request body or unconsumed streamed chunks.
  struct iwxstr      *out;          ///< Pending response payload.
  struct iwxstr      *owned;        ///< Buffer owned by the request (transfer buf API).
  const char *method;
  const char *target;
  const char *version;
  const char *scheme;
  const char *authority;
  const char *resp_body;
  void  (*resp_body_free)(void*);
  void *wf_data;
  void  (*wf_on_request_dispose)(struct iwn_http_req*);
  void  (*wf_on_response_headers_write)(struct iwn_http_req*);
  void *ws_data;
  iwn_http_server_chunk_handler chunk_cb;
  hive_data_source_t src;
  size_t   in_off;         ///< Consumed bytes of `in`.
  size_t   out_off;        ///< Consumed bytes of `out`.
  size_t   resp_body_len;
  size_t   resp_body_off;
  size_t   bstream_len;    ///< Length of the buffered request body.
  uint32_t stream_id;
  int      code;
  atomic_size_t out_pending;     ///< Bytes in `out` not yet accepted by hive.
  atomic_size_t pending_bytes;   ///< Bytes queued by a response writer from another thread.
  uint8_t       flags;
  bool remote_end;
  bool dispatched;
  bool in_chunk_delivery;
  bool resp_headers_sent;
  bool resp_ended;
  bool resp_eof;
  bool closed;
};

struct h2_out_pending {
  uint32_t       stream_id;
  struct iwxstr *data;
  iwn_http_server_chunk_handler chunk_cb;
  bool set_cb;
  bool eof;
  bool rst;
};

struct h2_conn {
  struct iwn_http_req *anchor;
  struct iwn_http_server_spec *spec;
  struct iwn_poller *poller;
  struct iwn_poller_adapter *pa;
  struct hive_session       *sess;
  struct hive_options       *hive_options;
  struct hive_callbacks      hive_callbacks;
  struct iwpool  *pool;
  struct iwhmap  *reqs;                  ///< stream_id -> struct h2_req*
  struct iwulist  reqlist;               ///< Live requests in creation order.
  struct iwulist  events;                ///< Pending app events.
  struct iwulist  graveyard;
  struct iwulist  out_queue;             ///< Deferred response writes, struct h2_out_pending*.
  struct iwxstr  *input_buf;
  pthread_mutex_t mtx;                   ///< Recursive. Guards session and all requests.
  pthread_mutex_t out_mtx;               ///< Leaf lock. Guards out_queue.
  atomic_bool     flush_scheduled;
  atomic_uint     refs;
  pthread_t       loop_tid;
  int  fd;
  int  active_streams;
  bool pa_closed;
  bool in_loop;
  bool write_wouldblock; ///< Transport write is blocked.
  bool io_progress;
  bool send_blocked;
  bool abort;
  bool closed;
};

/// Connection code (the poller event loop and the deferred flush task) marks
/// the current thread, so response writers can decide whether they may touch
/// the request state directly or have to queue the operation.
static _Thread_local struct h2_conn *tl_conn;

static struct h2_conn* _conn_ref(struct h2_conn *conn) {
  atomic_fetch_add_explicit(&conn->refs, 1, memory_order_relaxed);
  return conn;
}

static void _conn_unref(struct h2_conn *conn);
static void _conn_schedule_flush(struct h2_conn *conn);
static iwrc _conn_defer(
  struct h2_conn *conn, struct h2_req *req, const char *buf, size_t len,
  iwn_http_server_chunk_handler chunk_cb, bool eof, bool rst);

static void _conn_flush_locked(struct h2_conn *conn);
static void _req_dispatch(struct h2_req *req);

static inline bool _hive_rc_is_ok(int hrc) {
  return hrc == HIVE_OK || hrc == HIVE_ERR_WOULDBLOCK;
}

static inline bool _same_thread(pthread_t tid) {
  return pthread_equal(tid, pthread_self());
}

static inline bool _conn_is_owner(struct h2_conn *conn) {
  return (conn->in_loop && _same_thread(conn->loop_tid)) || (tl_conn == conn);
}

///////////////////////////////////////////////////////////////////////////
//                              Request                                    //
///////////////////////////////////////////////////////////////////////////

static void _req_out_clear(struct h2_req *req) {
  if (req->out) {
    iwxstr_clear(req->out);
  }
  req->out_off = 0;
  atomic_store_explicit(&req->out_pending, 0, memory_order_relaxed);
}

static iwrc _req_out_cat(struct h2_req *req, const char *buf, size_t len) {
  if (len == 0) {
    return 0;
  }
  if (!req->out) {
    req->out = iwxstr_create_empty();
    if (!req->out) {
      return iwrc_set_errno(IW_ERROR_ALLOC, errno);
    }
  }
  iwrc rc = iwxstr_cat(req->out, buf, len);
  if (!rc) {
    atomic_fetch_add_explicit(&req->out_pending, len, memory_order_relaxed);
  }
  return rc;
}

static inline bool _req_out_avail(struct h2_req *req) {
  return req->out && iwxstr_size(req->out) > req->out_off;
}

static inline bool _req_body_avail(struct h2_req *req) {
  return req->resp_body && req->resp_body_off < req->resp_body_len;
}

static inline bool _req_resp_has_data(struct h2_req *req) {
  return _req_out_avail(req) || _req_body_avail(req);
}

static void _req_free(struct h2_req *req) {
  if (!req) {
    return;
  }
  if (req->pub.on_request_dispose) {
    void (*dispose)(struct iwn_http_req*) = req->pub.on_request_dispose;
    req->pub.on_request_dispose = 0;
    dispose(&req->pub);
  }
  if (req->wf_on_request_dispose) {
    void (*dispose)(struct iwn_http_req*) = req->wf_on_request_dispose;
    req->wf_on_request_dispose = 0;
    dispose(&req->pub);
  }
  if (req->resp_body_free) {
    void (*free_fn)(void*) = req->resp_body_free;
    req->resp_body_free = 0;
    free_fn((void*) req->resp_body);
  }
  iwxstr_destroy(req->owned);
  iwxstr_destroy(req->in);
  iwxstr_destroy(req->out);
  pthread_mutex_destroy(&req->pub.user_mtx);
  iwpool_destroy(req->pool);
}

// Request API

static struct iwn_val _req_target(struct iwn_http_req *request) {
  struct h2_req *req = (void*) request;
  return (struct iwn_val) {
           .buf = (char*) req->target,
           .len = req->target ? strlen(req->target) : 0
  };
}

static struct iwn_val _req_method(struct iwn_http_req *request) {
  struct h2_req *req = (void*) request;
  return (struct iwn_val) {
           .buf = (char*) req->method,
           .len = req->method ? strlen(req->method) : 0
  };
}

static struct iwn_val _req_body(struct iwn_http_req *request) {
  struct h2_req *req = (void*) request;
  struct iwn_val ret = { 0 };
  if (req->flags & H2_REQ_STREAMED) {
    return ret;
  }
  if (req->in && req->bstream_len > 0) {
    ret.buf = iwxstr_ptr(req->in);
    ret.len = req->bstream_len;
  }
  return ret;
}

static bool _req_is_streamed(struct iwn_http_req *request) {
  return ((struct h2_req*) request)->flags & H2_REQ_STREAMED;
}

static bool _req_is_secure(struct iwn_http_req *request) {
  struct h2_req *req = (void*) request;
  return iwn_http_request_conn_is_secure(req->conn->anchor);
}

static bool _req_is_http2(struct iwn_http_req *request) {
  return true;
}

static const char* _req_remote_ip(struct iwn_http_req *request) {
  struct h2_req *req = (void*) request;
  return iwn_http_request_remote_ip(req->conn->anchor);
}

static struct iwn_val _req_header_get(struct iwn_http_req *request, const char *header_name, ssize_t header_name_len) {
  struct h2_req *req = (void*) request;
  if (header_name_len < 0) {
    header_name_len = strlen(header_name);
  }
  for (struct iwn_pair *p = req->headers.first; p; p = p->next) {
    if (  p->key_len == (size_t) header_name_len
       && strncasecmp(p->key, header_name, header_name_len) == 0) {
      return (struct iwn_val) {
               .buf = p->val,
               .len = p->val_len
      };
    }
  }
  return (struct iwn_val) {
           0
  };
}

static bool _req_headers_iterate(struct iwn_http_req *request, struct iwn_val *key, struct iwn_val *val, int *iter) {
  struct h2_req *req = (void*) request;
  if (*iter < 0) {
    return false;
  }
  struct iwn_pair *p = req->headers.first;
  for (int n = *iter; p && n > 0; --n) {
    p = p->next;
  }
  if (!p) {
    return false;
  }
  key->buf = (char*) p->key;
  key->len = p->key_len;
  val->buf = p->val;
  val->len = p->val_len;
  ++(*iter);
  return true;
}

static struct iwn_val _req_chunk_get(struct iwn_http_req *request) {
  struct h2_req *req = (void*) request;
  struct iwn_val ret = { 0 };
  if (!req->in) {
    return ret;
  }
  size_t size = iwxstr_size(req->in);
  if (req->in_off < size) {
    ret.buf = iwxstr_ptr(req->in) + req->in_off;
    ret.len = size - req->in_off;
  }
  return ret;
}

static void _req_chunk_deliver(struct h2_req *req) {
  if (req->in_chunk_delivery || !req->chunk_cb || req->closed) {
    return;
  }
  req->in_chunk_delivery = true;
  for (int i = 0; i < H2_MAX_CHUNK_ITER && req->chunk_cb && !req->closed; ++i) {
    struct iwn_val chunk = _req_chunk_get(&req->pub);
    if (chunk.len == 0 && !req->remote_end) {
      break;
    }
    bool again = false;
    if (!req->chunk_cb(&req->pub, &again)) {
      req->chunk_cb = 0;
      req->conn->abort = true;
      break;
    }
    if (chunk.len > 0) {
      req->in_off += chunk.len;
      if (req->in_off >= iwxstr_size(req->in)) {
        iwxstr_clear(req->in);
        req->in_off = 0;
      }
      continue;
    }
    break; // End of stream delivered
  }
  req->in_chunk_delivery = false;
}

static void _req_chunk_next(struct iwn_http_req *request, iwn_http_server_chunk_handler chunk_cb) {
  struct h2_req *req = (void*) request;
  req->chunk_cb = chunk_cb;
  if (!req->in_chunk_delivery) {
    _req_chunk_deliver(req);
  }
}

static void _connection_set_automatic(struct iwn_http_req *request) {
  ; // HTTP/2 connection lives as long as both sides need it
}

static void _connection_set_keep_alive(struct iwn_http_req *request, bool keep_alive) {
  ; // HTTP/2 has no keep-alive notion per request
}

static void _connection_set_upgrade(struct iwn_http_req *request) {
  ; // HTTP/2 upgrade is not supported
}

static bool _connection_is_upgrade(struct iwn_http_req *request) {
  return false;
}

// Response API

static iwrc _resp_code_set(struct iwn_http_req *request, int code) {
  if (code < 0 || code > 599) {
    return IW_ERROR_INVALID_ARGS;
  }
  ((struct h2_req*) request)->code = code ? code : 200;
  return 0;
}

static int _resp_code_get(struct iwn_http_req *request) {
  return ((struct h2_req*) request)->code;
}

static iwrc _resp_header_do(struct h2_req *req, const char *name, const char *value, ssize_t value_len, bool replace) {
  if (value_len < 0) {
    value_len = strlen(value);
  }
  size_t name_len = strlen(name);
  if (replace) {
    for (struct iwn_pair *p = req->resp_headers.first; p; p = p->next) {
      if (p->key_len == name_len && strcasecmp(p->key, name) == 0) {
        char *val = iwpool_strndup2(req->pool, value, value_len);
        if (!val) {
          return iwrc_set_errno(IW_ERROR_ALLOC, errno);
        }
        p->val = val;
        p->val_len = value_len;
        return 0;
      }
    }
  }
  char *lname = iwpool_strndup2(req->pool, name, name_len);
  if (!lname) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  for (char *c = lname; *c; ++c) {
    *c = (char) tolower((unsigned char) *c);
  }
  char *lval = iwpool_strndup2(req->pool, value, value_len);
  if (!lval) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  return iwn_pair_add_pool(req->pool, &req->resp_headers, lname, name_len, lval, value_len);
}

static iwrc _resp_header_add(struct iwn_http_req *request, const char *name, const char *value, ssize_t value_len) {
  return _resp_header_do((void*) request, name, value, value_len, false);
}

static iwrc _resp_header_set(struct iwn_http_req *request, const char *name, const char *value, ssize_t value_len) {
  return _resp_header_do((void*) request, name, value, value_len, true);
}

static struct iwn_val _resp_header_get(struct iwn_http_req *request, const char *name) {
  struct h2_req *req = (void*) request;
  for (struct iwn_pair *p = req->resp_headers.first; p; p = p->next) {
    if (strcasecmp(p->key, name) == 0) {
      return (struct iwn_val) {
               .buf = p->val,
               .len = p->val_len
      };
    }
  }
  return (struct iwn_val) {
           0
  };
}

static void _resp_body_clear(struct iwn_http_req *request) {
  struct h2_req *req = (void*) request;
  if (req->resp_body_free) {
    req->resp_body_free((void*) req->resp_body);
    req->resp_body_free = 0;
  }
  req->resp_body = 0;
  req->resp_body_len = 0;
  req->resp_body_off = 0;
}

static void _resp_body_set(struct iwn_http_req *request, const char *body, ssize_t body_len, void (*body_free)(void*)) {
  struct h2_req *req = (void*) request;
  _resp_body_clear(request);
  if (!body || body_len == 0) {
    return;
  }
  if (body_len < 0) {
    body_len = strlen(body);
  }
  req->resp_body = body;
  req->resp_body_len = body_len;
  req->resp_body_free = body_free;
}

static inline bool _h2_is_forbidden_header(const char *name, size_t name_len) {
  static const char *forbidden[] = {
    "connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade", 0
  };
  for (int i = 0; forbidden[i]; ++i) {
    if (strlen(forbidden[i]) == name_len && strncasecmp(forbidden[i], name, name_len) == 0) {
      return true;
    }
  }
  return false;
}

/// Builds and submits the response headers block for the given request.
static iwrc _resp_submit(struct h2_req *req) {
  iwrc rc = 0;
  struct h2_conn *conn = req->conn;
  struct hive_nv stack_nv[16];
  struct hive_nv *nv = stack_nv;
  size_t nv_cnt = 0, nv_cap = 16;
  char status[8];
  char clen[32];

  if (req->resp_headers_sent || req->closed || conn->abort) {
    return 0;
  }

  if (req->pub.on_response_headers_write) {
    req->pub.on_response_headers_write(&req->pub);
  }
  if (req->wf_on_response_headers_write) {
    req->wf_on_response_headers_write(&req->pub);
  }

  int hdr_cnt = 0;
  for (struct iwn_pair *p = req->resp_headers.first; p; p = p->next) {
    ++hdr_cnt;
  }
  // :status + headers + implicit content-length + date
  if ((size_t) hdr_cnt + 3 > nv_cap) {
    nv_cap = (size_t) hdr_cnt + 3;
    nv = malloc(nv_cap * sizeof(*nv));
    if (!nv) {
      return iwrc_set_errno(IW_ERROR_ALLOC, errno);
    }
  }
  memset(nv, 0, nv_cap * sizeof(*nv));

  int code = req->code ? req->code : 200;
  snprintf(status, sizeof(status), "%d", code);
  nv[nv_cnt++] = (struct hive_nv) {
    .name = (const uint8_t*) ":status",
    .name_len = IW_LLEN(":status"),
    .value = (const uint8_t*) status,
    .value_len = strlen(status),
  };

  bool chunked = (req->flags & (H2_REQ_CHUNKED_RESP | H2_REQ_STREAM_RESP)) != 0;
  bool has_clen = false;
  bool date_set = false;
  for (struct iwn_pair *p = req->resp_headers.first; p; p = p->next) {
    if (_h2_is_forbidden_header(p->key, p->key_len)) {
      continue;
    }
    if (p->key_len == IW_LLEN("content-length")) {
      has_clen = true;
    } else if (p->key_len == IW_LLEN("date")) {
      date_set = true;
    }
    nv[nv_cnt++] = (struct hive_nv) {
      .name = (const uint8_t*) p->key,
      .name_len = p->key_len,
      .value = (const uint8_t*) p->val,
      .value_len = p->val_len,
    };
  }

  if (  !has_clen
     && !chunked
     && code != 204 && code != 304 && (code < 100 || code > 199)) {
    size_t blen = req->resp_body_len + (req->out ? iwxstr_size(req->out) - req->out_off : 0);
    snprintf(clen, sizeof(clen), "%zu", blen);
    nv[nv_cnt++] = (struct hive_nv) {
      .name = (const uint8_t*) "content-length",
      .name_len = IW_LLEN("content-length"),
      .value = (const uint8_t*) clen,
      .value_len = strlen(clen),
    };
  }
  if (!date_set) {
    char date[32];
    iwn_http_request_server_date(conn->anchor, date);
    size_t date_len = strlen(date);
    if (date_len > 0 && nv_cnt < nv_cap) {
      char *v = iwpool_strndup2(req->pool, date, date_len);
      if (!v) {
        rc = iwrc_set_errno(IW_ERROR_ALLOC, errno);
        goto finish;
      }
      nv[nv_cnt++] = (struct hive_nv) {
        .name = (const uint8_t*) "date",
        .name_len = IW_LLEN("date"),
        .value = (const uint8_t*) v,
        .value_len = date_len,
      };
    }
  }

  bool with_src = chunked || _req_resp_has_data(req);
  hive_data_source_t *src = with_src ? &req->src : 0;

  int hrc = hive_submit_response(conn->sess, req->stream_id, nv, nv_cnt, src);
  if (hrc != HIVE_OK) {
    rc = IW_ERROR_FAIL;
    iwlog_error2("h2 | hive_submit_response() failed");
    goto finish;
  }
  req->resp_headers_sent = true;

finish:
  if (nv != stack_nv) {
    free(nv);
  }
  return rc;
}

// Forward declaration: the data source callback is registered at request creation.
static ssize_t _resp_read_cb(
  hive_session_t *session, uint32_t stream_id, uint8_t **buf, size_t length,
  uint32_t *data_flags, hive_data_source_t *source, void *user_data);

static iwrc _resp_end(struct iwn_http_req *request) {
  iwrc rc = 0;
  struct h2_req *req = (void*) request;
  if (req->resp_ended) {
    return 0;
  }
  req->resp_ended = true;
  req->resp_eof = true;
  req->chunk_cb = 0;
  RCC(rc, finish, _resp_submit(req));
  _conn_flush_locked(req->conn);
finish:
  return rc;
}

static iwrc _resp_transfer_buf(
  struct iwn_http_req *request,
  int                  status_code,
  const char          *content_type,
  struct iwxstr       *buf) {
  iwrc rc = 0;
  struct h2_req *req = (void*) request;
  RCC(rc, finish, iwn_http_response_code_set(request, status_code));
  if (!content_type) {
    content_type = "text/plain";
  }
  if (*content_type != '\0') {
    RCC(rc, finish, iwn_http_response_header_set(request, "content-type", content_type, -1));
  }
  iwxstr_destroy(req->owned);
  req->owned = buf;
  req->resp_body = iwxstr_ptr(buf);
  req->resp_body_len = iwxstr_size(buf);
  req->resp_body_off = 0;
  req->resp_body_free = 0;
  rc = _resp_end(request);

finish:
  if (rc) {
    iwxstr_destroy(buf);
  }
  return rc;
}

static iwrc _resp_stream_start(struct iwn_http_req *request, iwn_http_server_chunk_handler chunk_cb) {
  iwrc rc = 0;
  struct h2_req *req = (void*) request;
  req->chunk_cb = chunk_cb;
  if (req->resp_headers_sent) {
    return 0;
  }
  req->flags |= H2_REQ_STREAM_RESP;
  RCC(rc, finish, _resp_submit(req));
  _conn_flush_locked(req->conn);
finish:
  return rc;
}

static void _resp_stream_write(
  struct iwn_http_req *request, char *buf, ssize_t buf_len, void (*buf_free)(void*),
  iwn_http_server_chunk_handler chunk_cb, bool *again) {
  struct h2_req *req = (void*) request;
  iwrc rc = 0;
  if (buf_len < 0) {
    buf_len = buf ? (ssize_t) strlen(buf) : 0;
  }
  if (req->conn && !_conn_is_owner(req->conn)) {
    // Called from another thread: queue the operation for the connection
    // thread, which owns the libhive session and the request state.
    rc = _conn_defer(req->conn, req, buf, (size_t) buf_len, chunk_cb, chunk_cb == 0, false);
    if (buf && buf_free) {
      buf_free(buf);
    }
    if (chunk_cb && again) {
      *again = true;
    }
    if (rc) {
      iwlog_ecode_error3(rc);
    }
    return;
  }
  req->chunk_cb = chunk_cb;
  if (!chunk_cb) {
    req->resp_eof = true;
  } else {
    req->flags |= H2_REQ_STREAM_RESP;
  }
  if (buf && buf_len > 0) {
    RCC(rc, finish, _req_out_cat(req, buf, buf_len));
  }
  if (buf && buf_free) {
    buf_free(buf);
  }
  if (chunk_cb) {
    if (again) {
      *again = true;
    }
  }
  if (again && *again) {
    goto finish;
  }
  if (!req->resp_headers_sent) {
    RCC(rc, finish, _resp_submit(req));
  }
  req->conn->send_blocked = false;
  _conn_flush_locked(req->conn);

finish:
  if (rc) {
    iwlog_ecode_error3(rc);
    req->conn->abort = true;
  }
}

static void _resp_stream_end(struct iwn_http_req *request) {
  _resp_stream_write(request, 0, 0, 0, 0, 0);
}

static iwrc _resp_chunk_write(
  struct iwn_http_req *request, char *body, ssize_t body_len,
  iwn_http_server_chunk_handler chunk_cb, bool *again) {
  iwrc rc = 0;
  struct h2_req *req = (void*) request;
  if (body_len < 0) {
    body_len = body ? (ssize_t) strlen(body) : 0;
  }
  if (req->conn && !_conn_is_owner(req->conn)) {
    if (chunk_cb && again) {
      *again = true;
    }
    return _conn_defer(req->conn, req, body, (size_t) body_len, chunk_cb, false, false);
  }
  req->chunk_cb = chunk_cb;
  req->flags |= H2_REQ_CHUNKED_RESP;
  if (chunk_cb && again) {
    *again = true;
  }
  if (body && body_len > 0) {
    RCC(rc, finish, _req_out_cat(req, body, body_len));
  }
  if (!req->resp_headers_sent) {
    RCC(rc, finish, _resp_submit(req));
  }
  req->conn->send_blocked = false;
  if (!again || !*again) {
    _conn_flush_locked(req->conn);
  }
finish:
  return rc;
}

static iwrc _resp_chunk_end(struct iwn_http_req *request) {
  iwrc rc = 0;
  struct h2_req *req = (void*) request;
  if (req->conn && !_conn_is_owner(req->conn)) {
    return _conn_defer(req->conn, req, 0, 0, 0, true, false);
  }
  req->flags &= ~H2_REQ_CHUNKED_RESP;
  req->chunk_cb = 0;
  req->resp_eof = true;
  if (!req->resp_headers_sent) {
    RCC(rc, finish, _resp_submit(req));
  }
  req->conn->send_blocked = false;
  _conn_flush_locked(req->conn);
finish:
  return rc;
}

/// Aborts the request stream. Thread safe: an abort issued from another
/// thread is queued and executed by the connection thread.
static iwrc _req_abort(struct iwn_http_req *request) {
  struct h2_req *req = (void*) request;
  if (!req->conn) {
    return IW_ERROR_INVALID_STATE;
  }
  if (!_conn_is_owner(req->conn)) {
    return _conn_defer(req->conn, req, 0, 0, 0, true, true);
  }
  struct h2_conn *conn = req->conn;
  if (!conn->sess || conn->closed || conn->abort) {
    return IW_ERROR_INVALID_STATE;
  }
  req->chunk_cb = 0;
  req->resp_eof = true;
  if (hive_submit_rst_stream(conn->sess, req->stream_id, HIVE_H2_CANCEL) != HIVE_OK) {
    return IW_ERROR_FAIL;
  }
  conn->send_blocked = false;
  _conn_flush_locked(conn);
  return 0;
}

static size_t _req_pending(struct iwn_http_req *request) {
  struct h2_req *req = (void*) request;
  return atomic_load_explicit(&req->out_pending, memory_order_relaxed)
         + atomic_load_explicit(&req->pending_bytes, memory_order_relaxed);
}

// Framework glue

static void _req_wf_set(
  struct iwn_http_req *request, void *user_data,
  void (*wf_on_request_dispose)(struct iwn_http_req*),
  void (*wf_on_response_headers_write)(struct iwn_http_req*)) {
  struct h2_req *req = (void*) request;
  req->wf_data = user_data;
  req->wf_on_request_dispose = wf_on_request_dispose;
  req->wf_on_response_headers_write = wf_on_response_headers_write;
}

static void* _req_wf_data(struct iwn_http_req *request) {
  return ((struct h2_req*) request)->wf_data;
}

static void _req_ws_set(struct iwn_http_req *request, void *user_data) {
  ((struct h2_req*) request)->ws_data = user_data;
}

static void* _req_ws_data(struct iwn_http_req *request) {
  return ((struct h2_req*) request)->ws_data;
}

static void _req_poller_events_inject(struct iwn_http_req *request, iwn_on_poller_adapter_event eh) {
  iwlog_warn2("h2 | Poller events injection is not supported by the HTTP/2 transport");
}

static const struct iwn_http_req_ops _req_ops = {
  .request_target = _req_target,
  .request_method = _req_method,
  .request_body = _req_body,
  .request_is_streamed = _req_is_streamed,
  .request_is_secure = _req_is_secure,
  .request_is_http2 = _req_is_http2,
  .request_remote_ip = _req_remote_ip,
  .request_header_get = _req_header_get,
  .request_headers_iterate = _req_headers_iterate,
  .request_chunk_next = _req_chunk_next,
  .request_chunk_get = _req_chunk_get,
  .connection_set_automatic = _connection_set_automatic,
  .connection_set_keep_alive = _connection_set_keep_alive,
  .connection_set_upgrade = _connection_set_upgrade,
  .connection_is_upgrade = _connection_is_upgrade,
  .response_code_set = _resp_code_set,
  .response_code_get = _resp_code_get,
  .response_header_add = _resp_header_add,
  .response_header_set = _resp_header_set,
  .response_header_get = _resp_header_get,
  .response_body_clear = _resp_body_clear,
  .response_body_set = _resp_body_set,
  .response_end = _resp_end,
  .response_transfer_buf = _resp_transfer_buf,
  .response_chunk_write = _resp_chunk_write,
  .response_chunk_end = _resp_chunk_end,
  .response_stream_start = _resp_stream_start,
  .response_stream_write = _resp_stream_write,
  .response_stream_end = _resp_stream_end,
  .request_abort = _req_abort,
  .response_pending = _req_pending,
  .wf_set = _req_wf_set,
  .wf_data = _req_wf_data,
  .ws_set = _req_ws_set,
  .ws_data = _req_ws_data,
  .poller_events_inject = _req_poller_events_inject,
};

///////////////////////////////////////////////////////////////////////////
//                           Response data source                         //
///////////////////////////////////////////////////////////////////////////

static ssize_t _resp_read_cb(
  hive_session_t     *session,
  uint32_t            stream_id,
  uint8_t           **buf,
  size_t              length,
  uint32_t           *data_flags,
  hive_data_source_t *source,
  void               *user_data) {
  struct h2_req *req = source ? source->ptr : 0;
  if (!req || req->closed) {
    return HIVE_ERR_WOULDBLOCK;
  }
  for (int i = 0; i < H2_MAX_CHUNK_ITER; ++i) {
    if (_req_out_avail(req)) {
      size_t avail = iwxstr_size(req->out) - req->out_off;
      size_t n = avail < length ? avail : length;
      memcpy(*buf, iwxstr_ptr(req->out) + req->out_off, n);
      req->out_off += n;
      atomic_fetch_sub_explicit(&req->out_pending, n, memory_order_relaxed);
      if (req->out_off >= iwxstr_size(req->out)) {
        _req_out_clear(req);
      }
      if (req->resp_eof && !_req_resp_has_data(req)) {
        *data_flags |= HIVE_DATA_FLAG_EOF;
      }
      return (ssize_t) n;
    }
    if (_req_body_avail(req)) {
      // NOTE: The payload is always copied into the library send buffer.
      // A NO_COPY iovec may survive the hive_session_send() call (partial TLS writes)
      // and the request could be already disposed at that point.
      size_t avail = req->resp_body_len - req->resp_body_off;
      size_t n = avail < length ? avail : length;
      memcpy(*buf, req->resp_body + req->resp_body_off, n);
      req->resp_body_off += n;
      if (req->resp_eof && !_req_resp_has_data(req)) {
        *data_flags |= HIVE_DATA_FLAG_EOF;
      }
      return (ssize_t) n;
    }
    if (req->resp_eof) {
      *data_flags |= HIVE_DATA_FLAG_EOF;
      return 0;
    }
    if (req->chunk_cb) {
      struct h2_conn *conn = req->conn;
      bool again = false;
      bool ok = req->chunk_cb(&req->pub, &again);
      if (!ok) {
        conn->abort = true;
        return HIVE_ERR;
      }
      if (conn->abort) {
        return HIVE_ERR;
      }
      if (!again && !_req_resp_has_data(req) && !req->resp_eof) {
        // The data provider has nothing to send right now. A pending EOF is
        // still delivered by this invocation.
        break;
      }
      continue; // Consume the data produced by the provider (or deliver EOF).
    }
    break;
  }
  req->conn->send_blocked = true;
  return HIVE_ERR_WOULDBLOCK;
}

///////////////////////////////////////////////////////////////////////////
//                              Connection                                 //
///////////////////////////////////////////////////////////////////////////

static void _req_event_push(struct h2_conn *conn, struct h2_req *req, int type) {
  struct h2_event ev = { .req = req, .type = type };
  if (iwulist_push(&conn->events, &ev)) {
    iwlog_error2("h2 | Failed to queue request event");
    conn->abort = true;
  }
}

static void _req_dispatch(struct h2_req *req) {
  if (req->dispatched || req->closed) {
    return;
  }
  struct h2_conn *conn = req->conn;
  if (!(req->flags & H2_REQ_STREAMED) && !req->remote_end) {
    if (req->flags & H2_REQ_HAS_CONTENT_LEN) {
      // Wait for the complete body
      return;
    }
    // No content-length, the body (if any) will be delivered by chunks
    req->flags |= H2_REQ_STREAMED;
  }
  req->dispatched = true;

  if (req->flags & H2_REQ_BAD) {
    iwn_http_response_by_code(&req->pub, 400);
    return;
  }
  if (!(req->flags & H2_REQ_STREAMED)) {
    req->bstream_len = iwxstr_size(req->in);
  }
  if (!conn->spec->request_handler(&req->pub)) {
    conn->abort = true;
  }
}

static void _conn_drain_events(struct h2_conn *conn) {
  struct iwulist events = conn->events;
  iwulist_init(&conn->events, 16, sizeof(struct h2_event));

  for (size_t i = 0; i < iwulist_length(&events) && !conn->abort; ++i) {
    struct h2_event *ev = iwulist_get(&events, i);
    struct h2_req *req = ev->req;
    if (req->closed) {
      continue;
    }
    switch (ev->type) {
      case H2_EV_START:
        _req_dispatch(req);
        break;
      case H2_EV_DATA:
        _req_chunk_deliver(req);
        break;
      case H2_EV_END:
        if (!req->dispatched) {
          _req_dispatch(req);
        } else {
          _req_chunk_deliver(req);
        }
        break;
      default:
        break;
    }
  }
  iwulist_destroy_keep(&events);
}

static void _conn_graveyard_flush(struct h2_conn *conn) {
  for (size_t i = 0; i < iwulist_length(&conn->graveyard); ++i) {
    struct h2_req *req = *(struct h2_req**) iwulist_get(&conn->graveyard, i);
    _req_free(req);
  }
  iwulist_reset(&conn->graveyard);
}

static bool _conn_want_write(struct h2_conn *conn) {
  if (!conn->sess || hive_session_closed(conn->sess)) {
    return false;
  }
  if (hive_session_want_write(conn->sess, 1)) {
    return true;
  }
  if (conn->send_blocked) {
    return false;
  }
  for (size_t i = 0; i < iwulist_length(&conn->reqlist); ++i) {
    struct h2_req *req = *(struct h2_req**) iwulist_get(&conn->reqlist, i);
    if (req->closed) {
      continue;
    }
    if (req->resp_headers_sent && !req->resp_eof) {
      return true;
    }
    if (_req_resp_has_data(req)) {
      return true;
    }
  }
  return false;
}

static int _conn_send_rounds(struct h2_conn *conn) {
  int hrc = HIVE_OK;
  for (uint32_t rounds = 0; rounds < H2_MAX_SEND_ROUNDS && hrc == HIVE_OK && !conn->write_wouldblock; ++rounds) {
    if (!_conn_want_write(conn)) {
      break;
    }
    conn->io_progress = false;
    hrc = hive_session_send(conn->sess);
    if (hrc == HIVE_ERR_WOULDBLOCK) {
      conn->write_wouldblock = true;
      hrc = HIVE_OK;
      break;
    }
    if (hrc != HIVE_OK) {
      break;
    }
    if (conn->io_progress || conn->write_wouldblock) {
      continue;
    }
    if (!hive_session_want_write(conn->sess, 1)) {
      conn->send_blocked = true;
    }
    break;
  }
  return hrc;
}

static void _conn_flush_locked(struct h2_conn *conn) {
  if (  !conn->sess || conn->pa_closed || conn->closed || conn->abort
     || (conn->in_loop && _same_thread(conn->loop_tid))) {
    return;
  }
  int hrc = _conn_send_rounds(conn);
  if (!_hive_rc_is_ok(hrc)) {
    conn->abort = true;
    return;
  }
  if (conn->pa && _conn_want_write(conn)) {
    conn->pa->arm(conn->pa, IWN_POLLOUT);
  }
}

static void _conn_update_timeout(struct h2_conn *conn) {
  struct iwn_http_server_spec *spec = conn->spec;
  if (!conn->poller || conn->fd < 0) {
    return;
  }
  int timeout = conn->active_streams > 0 ? spec->request_timeout_sec : spec->request_timeout_keepalive_sec;
  if (timeout > 0) {
    iwn_poller_set_timeout(conn->poller, conn->fd, timeout);
  }
}

static void _conn_update_remote_ends(struct h2_conn *conn) {
  for (size_t i = 0; i < iwulist_length(&conn->reqlist); ++i) {
    struct h2_req *req = *(struct h2_req**) iwulist_get(&conn->reqlist, i);
    if (req->remote_end || req->closed) {
      continue;
    }
    hive_stream_state_t st = hive_stream_get_state(conn->sess, req->stream_id);
    if (st == HIVE_STREAM_HALF_CLOSED_REMOTE || st == HIVE_STREAM_CLOSED) {
      req->remote_end = true;
      _req_event_push(conn, req, H2_EV_END);
    }
  }
}

static ssize_t _hcb_send(hive_session_t *session, const struct iovec *iov, int iovcnt, void *user_data) {
  struct h2_conn *conn = user_data;
  if (!conn->pa || iovcnt < 1) {
    return 0;
  }
  ssize_t total = 0;
  for (int i = 0; i < iovcnt; ++i) {
    const uint8_t *base = iov[i].iov_base;
    size_t left = iov[i].iov_len;
    while (left > 0) {
      ssize_t ret = conn->pa->write(conn->pa, base, left);
      if (ret > 0) {
        total += ret;
        base += ret;
        left -= (size_t) ret;
        conn->io_progress = true;
        continue;
      }
      if (ret == -1 && errno == EINTR) {
        continue;
      }
      if (ret == -1 && (errno == EWOULDBLOCK || errno == EAGAIN)) {
        conn->write_wouldblock = true;
        return total;
      }
      if (ret == 0) {
        // No progress is possible right now
        conn->write_wouldblock = true;
        return total;
      }
      return -1;
    }
  }
  return total;
}

static int _hcb_on_begin_headers(hive_session_t *session, uint32_t stream_id, void *user_data) {
  struct h2_conn *conn = user_data;
  struct h2_req *req = 0;
  struct iwpool *pool = 0;
  struct iwxstr *in = 0;

  if (iwhmap_get_u32(conn->reqs, stream_id)) {
    return 0; // Trailers of an existing request
  }
  pool = iwpool_create_empty();
  if (!pool) {
    return HIVE_ERR_NOMEM;
  }
  req = iwpool_calloc(sizeof(*req), pool);
  in = iwxstr_create_empty();
  if (!req || !in) {
    iwxstr_destroy(in);
    iwpool_destroy(pool);
    return HIVE_ERR_NOMEM;
  }
  req->pool = pool;
  req->conn = conn;
  req->pub.impl = &_req_ops;
  req->pub.poller_adapter = conn->pa;
  req->pub.server_user_data = conn->spec->user_data;
  req->in = in;
  req->stream_id = stream_id;
  req->code = 200;
  atomic_init(&req->out_pending, 0);
  atomic_init(&req->pending_bytes, 0);
  req->src.ptr = req;
  req->src.read_callback = _resp_read_cb;

  pthread_mutexattr_t attr;
  pthread_mutexattr_init(&attr);
  pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
  pthread_mutex_init(&req->pub.user_mtx, &attr);
  pthread_mutexattr_destroy(&attr);

  if (iwhmap_put_u32(conn->reqs, stream_id, req)) {
    pthread_mutex_destroy(&req->pub.user_mtx);
    iwxstr_destroy(in);
    iwpool_destroy(pool);
    return HIVE_ERR_NOMEM;
  }
  if (iwulist_push(&conn->reqlist, &req)) {
    iwhmap_remove_u32(conn->reqs, stream_id);
    pthread_mutex_destroy(&req->pub.user_mtx);
    iwxstr_destroy(in);
    iwpool_destroy(pool);
    return HIVE_ERR_NOMEM;
  }
  ++conn->active_streams;
  return 0;
}

static int _hcb_on_header(
  hive_session_t *session, uint32_t stream_id,
  hive_buf_t *name, hive_buf_t *value, uint8_t flags, void *user_data) {
  struct h2_conn *conn = user_data;
  struct h2_req *req = iwhmap_get_u32(conn->reqs, stream_id);
  if (!req || !name->data) {
    return 0;
  }
  char *n = iwpool_strndup2(req->pool, (const char*) name->data, name->len);
  char *v = iwpool_strndup2(req->pool, value && value->data ? (const char*) value->data : "", value ? value->len : 0);
  if (!n || !v) {
    return HIVE_ERR_NOMEM;
  }
  if (n[0] == ':') {
    if (strcmp(n, ":method") == 0) {
      req->method = v;
    } else if (strcmp(n, ":path") == 0) {
      req->target = v;
    } else if (strcmp(n, ":scheme") == 0) {
      req->scheme = v;
    } else if (strcmp(n, ":authority") == 0) {
      req->authority = v;
    }
    return 0;
  }
  if (iwn_pair_add_pool(req->pool, &req->headers, n, name->len, v, value ? value->len : 0)) {
    return HIVE_ERR_NOMEM;
  }
  return 0;
}

static int _hcb_on_headers_complete(hive_session_t *session, uint32_t stream_id, uint8_t flags, void *user_data) {
  struct h2_conn *conn = user_data;
  struct h2_req *req = iwhmap_get_u32(conn->reqs, stream_id);
  if (!req) {
    return 0;
  }
  if (req->target && req->target[0] != '/') {
    // Absolute-form targets are not supported
    req->flags |= H2_REQ_BAD;
  }
  if (!req->method || !req->target) {
    req->flags |= H2_REQ_BAD;
  }
  if (!req->version) {
    req->version = "HTTP/2.0";
  }

  struct iwn_val clen = iwn_pair_find_val(&req->headers, "content-length", -1);
  if (clen.len) {
    req->flags |= H2_REQ_HAS_CONTENT_LEN;
    int64_t cl = 0;
    if (iwn_val_i64(&clen, -1, &cl) != 0 || cl < 0) {
      req->flags |= H2_REQ_BAD;
    } else if (cl > conn->spec->request_buf_max_size) {
      req->flags |= H2_REQ_STREAMED;
    }
  }
  _req_event_push(conn, req, H2_EV_START);
  return 0;
}

static int _hcb_on_data_chunk(
  hive_session_t *session, uint32_t stream_id,
  const uint8_t *data, size_t len, uint8_t flags, void *user_data) {
  struct h2_conn *conn = user_data;
  struct h2_req *req = iwhmap_get_u32(conn->reqs, stream_id);
  if (!req) {
    return 0;
  }
  if (len > 0) {
    size_t pending = iwxstr_size(req->in) - req->in_off;
    size_t limit = (size_t) conn->spec->request_buf_max_size;
    // Nobody consumes the streamed body and the buffered amount exceeds the limit.
    if (!req->chunk_cb && pending + len > limit) {
      iwlog_warn("h2 | Request body of stream: %u exceeds the maximum size: %zu", stream_id, limit);
      return HIVE_ERR_REFUSED_STREAM;
    }
    if (iwxstr_cat(req->in, data, len)) {
      return HIVE_ERR_NOMEM;
    }
    _req_event_push(conn, req, H2_EV_DATA);
  }
  return 0;
}

static int _hcb_on_stream_close(hive_session_t *session, uint32_t stream_id, uint32_t error_code, void *user_data) {
  struct h2_conn *conn = user_data;
  struct h2_req *req = iwhmap_get_u32(conn->reqs, stream_id);
  if (!req) {
    return 0;
  }
  req->closed = true;
  iwhmap_remove_u32(conn->reqs, stream_id);
  iwulist_remove_first_by(&conn->reqlist, &req);
  if (conn->active_streams > 0) {
    --conn->active_streams;
  }
  if (!req->remote_end) {
    req->remote_end = true;
  }
  if (iwulist_push(&conn->graveyard, &req)) {
    conn->abort = true;
  }
  return 0;
}

static int _hcb_on_goaway(
  hive_session_t *session, uint32_t last_stream_id, uint32_t error_code,
  const uint8_t *debug_data, size_t debug_len, void *user_data) {
  struct h2_conn *conn = user_data;
  conn->closed = true;
  return 0;
}

static int _hcb_on_connection_error(hive_session_t *session, int hive_err, uint32_t h2_error_code, void *user_data) {
  struct h2_conn *conn = user_data;
  conn->closed = true;
  if (!conn->abort) {
    iwlog_warn("h2 | Connection error: %d, HTTP/2 code: %u", hive_err, h2_error_code);
  }
  return 0;
}

///////////////////////////////////////////////////////////////////////////
//                     Deferred response writes                           //
///////////////////////////////////////////////////////////////////////////

/// Response writers which are not running on the connection thread queue
/// their data here. The queue is guarded by the leaf `out_mtx` lock, the data
/// is applied to the requests by the connection thread (`_conn_flush_pending_locked()`)
/// under `conn->mtx`. This keeps the libhive session single threaded while the
/// public response data API stays thread safe.

static struct h2_out_pending* _conn_pending_get_locked(struct h2_conn *conn, uint32_t stream_id) {
  for (size_t i = 0; i < iwulist_length(&conn->out_queue); ++i) {
    struct h2_out_pending *p = *(struct h2_out_pending**) iwulist_get(&conn->out_queue, i);
    if (p->stream_id == stream_id) {
      return p;
    }
  }
  struct h2_out_pending *p = calloc(1, sizeof(*p));
  if (!p) {
    return 0;
  }
  p->stream_id = stream_id;
  p->data = iwxstr_create_empty();
  if (!p->data || iwulist_push(&conn->out_queue, &p)) {
    iwxstr_destroy(p->data);
    free(p);
    return 0;
  }
  return p;
}

static iwrc _conn_defer_locked(
  struct h2_conn *conn, struct h2_req *req, const char *buf, size_t len,
  iwn_http_server_chunk_handler chunk_cb, bool eof, bool rst) {
  struct h2_out_pending *p = _conn_pending_get_locked(conn, req->stream_id);
  if (!p) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  if (len) {
    iwrc rc = iwxstr_cat(p->data, buf, len);
    if (rc) {
      return rc;
    }
    atomic_fetch_add_explicit(&req->pending_bytes, len, memory_order_relaxed);
  }
  if (chunk_cb) {
    p->chunk_cb = chunk_cb;
    p->set_cb = true;
  }
  if (eof) {
    p->eof = true;
  }
  if (rst) {
    p->rst = true;
  }
  return 0;
}

static iwrc _conn_defer(
  struct h2_conn *conn, struct h2_req *req, const char *buf, size_t len,
  iwn_http_server_chunk_handler chunk_cb, bool eof, bool rst) {
  if (!conn || !req || !conn->sess || conn->closed || conn->abort) {
    return IW_ERROR_INVALID_STATE;
  }
  pthread_mutex_lock(&conn->out_mtx);
  iwrc rc = _conn_defer_locked(conn, req, buf, len, chunk_cb, eof, rst);
  pthread_mutex_unlock(&conn->out_mtx);
  if (!rc) {
    _conn_schedule_flush(conn);
  }
  return rc;
}

/// Moves the deferred writes of the connection into the request output
/// buffers. Must be called on the connection thread with `conn->mtx` held.
static void _conn_flush_pending_locked(struct h2_conn *conn) {
  // The queue is appended to by _conn_defer_locked() under the leaf `out_mtx`
  // lock; the swap must be serialized by the very same lock, otherwise a
  // concurrent writer can push an entry into the list being detached and leave
  // a dangling pointer in `conn->out_queue`.
  pthread_mutex_lock(&conn->out_mtx);
  struct iwulist batch = conn->out_queue;
  iwulist_init(&conn->out_queue, 16, sizeof(struct h2_out_pending*));
  pthread_mutex_unlock(&conn->out_mtx);
  size_t count = iwulist_length(&batch);
  if (!count) {
    iwulist_destroy_keep(&batch);
    return;
  }
  for (size_t i = 0; i < count; ++i) {
    struct h2_out_pending *p = *(struct h2_out_pending**) iwulist_get(&batch, i);
    struct h2_req *req = conn->reqs ? iwhmap_get_u32(conn->reqs, p->stream_id) : 0;
    size_t len = p->data ? iwxstr_size(p->data) : 0;
    if (req && len) {
      if (atomic_load_explicit(&req->pending_bytes, memory_order_relaxed) >= len) {
        atomic_fetch_sub_explicit(&req->pending_bytes, len, memory_order_relaxed);
      } else {
        atomic_store_explicit(&req->pending_bytes, 0, memory_order_relaxed);
      }
    }
    if (req && !req->closed && conn->sess) {
      if (p->rst) {
        req->resp_eof = true;
        req->chunk_cb = 0;
        if (hive_submit_rst_stream(conn->sess, p->stream_id, HIVE_H2_CANCEL) != HIVE_OK) {
          conn->abort = true;
        }
      } else {
        if (p->set_cb) {
          req->chunk_cb = p->chunk_cb;
          req->flags |= H2_REQ_STREAM_RESP;
        }
        if (len && _req_out_cat(req, iwxstr_ptr(p->data), len)) {
          conn->abort = true;
        }
        if (p->eof) {
          req->resp_eof = true;
          req->chunk_cb = 0;
          req->flags &= ~H2_REQ_CHUNKED_RESP;
        }
        if ((p->set_cb || len || p->eof) && !req->resp_headers_sent) {
          if (_resp_submit(req)) {
            conn->abort = true;
          }
        }
      }
    }
    iwxstr_destroy(p->data);
    free(p);
  }
  iwulist_destroy_keep(&batch);
  if (!conn->abort) {
    conn->send_blocked = false;
    _conn_flush_locked(conn);
  }
}

static void _conn_flush_task(void *arg) {
  struct h2_conn *conn = arg;
  atomic_store_explicit(&conn->flush_scheduled, false, memory_order_release);
  struct h2_conn *prev_tl = tl_conn;
  pthread_mutex_lock(&conn->mtx);
  tl_conn = conn;
  if (!conn->closed && !conn->abort && !conn->pa_closed && conn->sess) {
    _conn_flush_pending_locked(conn);
  }
  tl_conn = prev_tl;
  pthread_mutex_unlock(&conn->mtx);
  _conn_unref(conn);
}

static void _conn_schedule_flush(struct h2_conn *conn) {
  if (!conn->poller) {
    return;
  }
  if (atomic_exchange_explicit(&conn->flush_scheduled, true, memory_order_acq_rel)) {
    return;
  }
  if (iwn_poller_task(conn->poller, _conn_flush_task, _conn_ref(conn))) {
    atomic_store_explicit(&conn->flush_scheduled, false, memory_order_release);
    _conn_unref(conn);
  }
}

static void _conn_unref(struct h2_conn *conn) {
  if (!conn || atomic_fetch_sub_explicit(&conn->refs, 1, memory_order_acq_rel) != 1) {
    return;
  }
  pthread_mutex_lock(&conn->out_mtx);
  for (size_t i = 0; i < iwulist_length(&conn->out_queue); ++i) {
    struct h2_out_pending *p = *(struct h2_out_pending**) iwulist_get(&conn->out_queue, i);
    iwxstr_destroy(p->data);
    free(p);
  }
  iwulist_destroy_keep(&conn->out_queue);
  pthread_mutex_unlock(&conn->out_mtx);
  pthread_mutex_destroy(&conn->out_mtx);
  pthread_mutex_destroy(&conn->mtx);
  if (conn->pool) {
    iwpool_destroy(conn->pool);
  }
  free(conn);
}

static void _conn_dispose(struct iwn_http_req *anchor) {
  struct h2_conn *conn = iwn_http_request_transport_data(anchor);
  if (!conn) {
    return;
  }
  iwn_http_request_transport_set(anchor, 0, 0);
  conn->pa_closed = true;
  conn->pa = 0;
  conn->closed = true;

  pthread_mutex_lock(&conn->mtx);

  for (size_t i = 0; i < iwulist_length(&conn->reqlist); ++i) {
    struct h2_req *req = *(struct h2_req**) iwulist_get(&conn->reqlist, i);
    req->closed = true;
    _req_free(req);
  }
  iwulist_destroy_keep(&conn->reqlist);
  _conn_graveyard_flush(conn);

  iwhmap_destroy(conn->reqs);
  conn->reqs = 0;
  iwulist_destroy_keep(&conn->events);
  iwulist_destroy_keep(&conn->graveyard);
  iwxstr_destroy(conn->input_buf);
  conn->input_buf = 0;
  if (conn->sess) {
    hive_session_free(conn->sess);
    conn->sess = 0;
  }
  if (conn->hive_options) {
    hive_options_free(conn->hive_options);
    conn->hive_options = 0;
  }
  // Deferred writes which were not flushed yet are dropped by _conn_unref()
  // when the last reference (a pending flush task) is released.
  pthread_mutex_unlock(&conn->mtx);
  _conn_unref(conn);
}

static int64_t _conn_on_event(struct iwn_poller_adapter *pa, void *user_data, uint32_t events) {
  struct iwn_http_req *anchor = user_data;
  struct h2_conn *conn = iwn_http_request_transport_data(anchor);
  if (!conn) {
    return -1;
  }
  conn->pa = pa;

  pthread_mutex_lock(&conn->mtx);

  if (conn->pa_closed || conn->closed || conn->abort || !conn->sess) {
    pthread_mutex_unlock(&conn->mtx);
    return -1;
  }
  if (conn->in_loop) {
    // Re-entered from a callback
    pthread_mutex_unlock(&conn->mtx);
    return 0;
  }

  int64_t ret = IWN_POLLIN;
  int hrc = HIVE_OK;
  uint8_t buf[8192];
  bool input_consumed = false;
  struct hive_session *sess = conn->sess;

  conn->in_loop = true;
  conn->loop_tid = pthread_self();
  conn->write_wouldblock = false;

  // Apply response data queued by writers from other threads.
  _conn_flush_pending_locked(conn);
  if (conn->abort) {
    goto finish;
  }

  hrc = _conn_send_rounds(conn);
  if (!_hive_rc_is_ok(hrc)) {
    goto finish;
  }

  while (iwxstr_size(conn->input_buf) > 0 && hive_session_want_read(sess)) {
    size_t blen = iwxstr_size(conn->input_buf);
    ssize_t consumed = hive_session_recv(sess, (uint8_t*) iwxstr_ptr(conn->input_buf), blen);
    if (consumed < 0) {
      hrc = hive_session_last_error(sess);
      goto finish;
    }
    input_consumed = input_consumed || consumed > 0;
    iwxstr_shift(conn->input_buf, (size_t) consumed);
    if ((size_t) consumed < blen) {
      break;
    }
  }

  while (iwxstr_size(conn->input_buf) == 0 && hive_session_want_read(sess)) {
    ssize_t n = pa->read(pa, buf, sizeof(buf));
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      } else if (errno == EWOULDBLOCK || errno == EAGAIN) {
        break;
      }
      iwlog_ecode_error3(iwrc_set_errno(IW_ERROR_IO_ERRNO, errno));
      conn->abort = true;
      goto finish;
    } else if (n == 0) {
      conn->closed = true;
      goto finish;
    }
    ssize_t consumed = hive_session_recv(sess, buf, (size_t) n);
    if (consumed < 0) {
      hrc = hive_session_last_error(sess);
      goto finish;
    }
    input_consumed = input_consumed || consumed > 0;
    if (consumed < n) {
      if (iwxstr_cat(conn->input_buf, buf + consumed, (size_t) (n - consumed))) {
        conn->abort = true;
        goto finish;
      }
      break;
    }
    // Give the application a chance to consume the request body between reads,
    // so buffered streamed data does not grow with the socket throughput.
    if (iwulist_length(&conn->events) > 0) {
      _conn_update_remote_ends(conn);
      _conn_drain_events(conn);
      if (conn->abort) {
        goto finish;
      }
      if (conn->send_blocked) {
        conn->send_blocked = false;
      }
      hrc = _conn_send_rounds(conn);
      if (!_hive_rc_is_ok(hrc)) {
        goto finish;
      }
      conn->write_wouldblock = false;
    }
  }

  if (conn->send_blocked && input_consumed) {
    conn->send_blocked = false;
  }

  _conn_update_remote_ends(conn);
  _conn_drain_events(conn);
  if (conn->abort) {
    goto finish;
  }

  hrc = _conn_send_rounds(conn);
  if (!_hive_rc_is_ok(hrc)) {
    goto finish;
  }
  if (conn->send_blocked && input_consumed) {
    conn->send_blocked = false;
    hrc = _conn_send_rounds(conn);
    if (!_hive_rc_is_ok(hrc)) {
      goto finish;
    }
  }

  _conn_update_timeout(conn);

  ret = 0;
  if (hive_session_want_read(sess)) {
    ret |= IWN_POLLIN;
  }
  if (_conn_want_write(conn) || (conn->pa && conn->pa->has_pending_write_bytes(conn->pa))) {
    ret |= IWN_POLLOUT;
  }

finish:
  if (!_hive_rc_is_ok(hrc)) {
    conn->abort = true;
  }
  if (conn->abort) {
    ret = -1;
  }
  conn->in_loop = false;
  memset(&conn->loop_tid, 0, sizeof(conn->loop_tid));
  _conn_graveyard_flush(conn);
  pthread_mutex_unlock(&conn->mtx);

  if (conn->abort || conn->closed) {
    ret = -1;
  }
  return ret;
}

static struct h2_conn* _conn_create(struct iwn_http_req *anchor) {
  struct h2_conn *conn = 0;
  struct iwxstr *input_buf = 0;
  struct iwhmap *reqs = 0;
  struct hive_options *opt = 0;

  conn = calloc(1, sizeof(*conn));
  if (!conn) {
    return 0;
  }
  conn->pool = iwpool_create_empty();
  if (!conn->pool) {
    free(conn);
    return 0;
  }
  atomic_init(&conn->refs, 1);
  atomic_init(&conn->flush_scheduled, false);
  // Both mutexes and the deferred write queue must be initialized before the
  // first `goto fail` so that _conn_unref() can dispose them unconditionally.
  pthread_mutexattr_t attr;
  pthread_mutexattr_init(&attr);
  pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
  pthread_mutex_init(&conn->mtx, &attr);
  pthread_mutexattr_destroy(&attr);
  pthread_mutex_init(&conn->out_mtx, 0);
  iwulist_init(&conn->out_queue, 16, sizeof(struct h2_out_pending*));

  conn->anchor = anchor;
  conn->spec = iwn_http_request_server_spec(anchor);
  conn->pa = anchor->poller_adapter;
  if (!conn->pa) {
    goto fail;
  }
  conn->poller = conn->pa->poller;
  conn->fd = conn->pa->fd;

  reqs = iwhmap_create_u32(0);
  input_buf = iwxstr_create_empty();
  if (!reqs || !input_buf) {
    goto fail;
  }
  conn->reqs = reqs;
  conn->input_buf = input_buf;
  iwulist_init(&conn->reqlist, 16, sizeof(struct h2_req*));
  iwulist_init(&conn->events, 16, sizeof(struct h2_event));
  iwulist_init(&conn->graveyard, 16, sizeof(struct h2_req*));

  opt = hive_options_new();
  if (!opt) {
    goto fail;
  }
  conn->hive_options = opt;
  if (conn->spec->request_max_headers_count > 0) {
    hive_options_set_max_header_count(opt, (uint32_t) conn->spec->request_max_headers_count);
  }
  if (conn->spec->request_buf_max_size > 0) {
    hive_options_set_max_header_list_size(opt, (uint32_t) conn->spec->request_buf_max_size);
  }

  memset(&conn->hive_callbacks, 0, sizeof(conn->hive_callbacks));
  conn->hive_callbacks.on_begin_headers = _hcb_on_begin_headers;
  conn->hive_callbacks.on_header = _hcb_on_header;
  conn->hive_callbacks.on_headers_complete = _hcb_on_headers_complete;
  conn->hive_callbacks.on_data_chunk = _hcb_on_data_chunk;
  conn->hive_callbacks.on_stream_close = _hcb_on_stream_close;
  conn->hive_callbacks.on_goaway = _hcb_on_goaway;
  conn->hive_callbacks.on_connection_error = _hcb_on_connection_error;
  conn->hive_callbacks.send = _hcb_send;

  conn->sess = hive_session_server_new(0, opt, &conn->hive_callbacks, conn);
  if (!conn->sess) {
    iwlog_error2("h2 | Failed to create HTTP/2 session");
    goto fail;
  }

  iwn_http_request_transport_set(anchor, conn, _conn_dispose);
  iwn_http_inject_poller_events_handler(anchor, _conn_on_event);
  return conn;

fail:
  if (conn->sess) {
    hive_session_free(conn->sess);
    conn->sess = 0;
  }
  if (conn->hive_options) {
    hive_options_free(conn->hive_options);
    conn->hive_options = 0;
  }
  iwxstr_destroy(conn->input_buf);
  conn->input_buf = 0;
  iwhmap_destroy(conn->reqs);
  conn->reqs = 0;
  iwulist_destroy_keep(&conn->reqlist);
  iwulist_destroy_keep(&conn->events);
  iwulist_destroy_keep(&conn->graveyard);
  _conn_unref(conn);
  return 0;
}

bool iwn_http2_conn_attach_alpn(struct iwn_http_req *request) {
  struct iwn_poller_adapter *pa = request->poller_adapter;
  if (!pa || !pa->get_protocol_name) {
    return false;
  }
  const char *proto = pa->get_protocol_name(pa);
  if (!proto || strcmp(proto, "h2") != 0) {
    return false;
  }
  return _conn_create(request) != 0;
}

bool iwn_http2_conn_attach_preface(struct iwn_http_req *request, const uint8_t *buf, size_t len) {
  static const char magic[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
  struct h2_conn *conn = _conn_create(request);
  if (!conn) {
    return false;
  }
  if (hive_session_recv(conn->sess, (const uint8_t*) magic, sizeof(magic) - 1) < 0) {
    iwlog_error2("h2 | Failed to feed the HTTP/2 client preface");
    goto fail;
  }
  if (len > 0 && iwxstr_cat(conn->input_buf, buf, len)) {
    iwlog_error2("h2 | Failed to buffer the already read connection data");
    goto fail;
  }
  return true;

fail:
  _conn_dispose(request);
  return false;
}

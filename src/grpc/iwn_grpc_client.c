#include "iwn_grpc_client.h"
#include "iwn_url.h"
#include "iwn_pairs.h"
#include "ssl/iwn_brssl_poller_adapter.h"
#include "poller/iwn_direct_poller_adapter.h"

#include <iowow/iwrefs.h>
#include <iowow/iwlog.h>
#include <iowow/iwpool.h>
#include <iowow/iwutils.h>
#include <iowow/iwxstr.h>
#include <iowow/iwarr.h>
#include <iowow/iwhmap.h>
#include <iowow/iwconv.h>

#include <hive.h>
#include <string.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#define _FLAG_SECURE     0x100U
#define _FLAG_NO_NETWORK 0x200U

enum _rx_state {
  _RX_HEADER,
  _RX_BODY,
  _RX_STOP,
};

struct _rx {
  enum _rx_state state;
  /* gRPC message prefix: 1 byte compressed flag + 4 bytes big-endian length. */
  uint8_t header[5];
  size_t  header_len;

  uint32_t body_len;
  size_t   body_off;
  uint8_t *body;
  uint8_t  compressed;
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

struct _request {
  struct iwref_holder     ref;
  struct iwn_grpc_client *client;
  struct iwpool *pool;
  struct iwn_grpc_req_spec spec;
  struct _rx rx;
  struct _msg_slot *mslots;

  iwrc  rc;
  int   http_status;
  int   grpc_status;
  char *error_explained;
  char *data_encoding;
  char *output_data_encoding;

  uint32_t stream_id;
  bool     client_streaming; ///< Continous streaming of client messages

  volatile bool close_pending;
  volatile bool half_close_pending;
};

struct _deferred_callback {
  struct iwn_grpc_client *client;
  iwrc     (*execute)(const struct _deferred_callback*);
  uint64_t error_code;
  uint32_t stream_id;
  bool     immediate; ///< Try execute deferred callback immediately.
};

struct iwn_grpc_client {
  struct iwref_holder ref;
  struct iwn_poller  *poller;
  struct iwpool      *pool;
  struct iwn_poller_adapter *pa;

  struct hive_session  *sess;
  struct hive_callbacks hive_callbacks;
  struct hive_options  *hive_options;
  struct iwxstr *input_buf;

  struct iwn_grpc_client_spec spec;
  struct iwn_url url;

  pthread_mutex_t mtx;
  struct iwhmap  *requests_map;
  struct iwulist  deferred_callbacks;

  int      fd;              ///< Connection file descriptor
  unsigned flags;

  bool io_wouldblock;

  volatile iwrc rc;
  volatile bool goaway_submitted;
  volatile bool closed_by_api;
  volatile bool connected;
  volatile bool pa_closed; ///< Poller adapter is not operable it this state.
  volatile bool in_loop;   ///< True if we are inside event loop callbacks;
};

static inline bool _hive_is_stream_closed(int stream_state) {
  switch (stream_state) {
    case HIVE_STREAM_HALF_CLOSED_LOCAL:
    case HIVE_STREAM_HALF_CLOSED_REMOTE:
    case HIVE_STREAM_CLOSED:
      return true;
    default:
      return false;
  }
}

static void _msg_slot_destroy(struct _msg_slot *slot) {
  if (slot && slot->pool) {
    iwpool_destroy(slot->pool);
  }
}

static iwrc _grpc2rc(int err) {
  if (!err) {
    return 0;
  }
  static iwrc _codes[] = {
    GRPC_ERROR_CANCELLED,
    GRPC_ERROR,
    GRPC_ERROR_INVALID_ARGUMENT,
    GRPC_ERROR_DEADLINE_EXCEEDED,
    GRPC_ERROR_NOT_FOUND,
    GRPC_ERROR_ALREADY_EXISTS,
    GRPC_ERROR_PERMISSION_DENIED,
    GRPC_ERROR_RESOURCE_EXHAUSTED,
    GRPC_ERROR_FAILED_PRECONDITION,
    GRPC_ERROR_ABORTED,
    GRPC_ERROR_OUT_OF_RANGE,
    GRPC_ERROR_UNIMPLEMENTED,
    GRPC_ERROR_INTERNAL,
    GRPC_ERROR_UNAVAILABLE,
    GRPC_ERROR_DATA_LOSS,
    GRPC_ERROR_UNAUTHENTICATED,
  };
  if (err > 0 && err <= sizeof(_codes) / sizeof(_codes[0])) {
    return _codes[err - 1];
  } else {
    return GRPC_ERROR;
  }
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
    case HIVE_H2_CANCEL:
      return 0; // Do not treat stream cancellation as and error (GRPC_ERROR_H2_CANCEL)
    default:
      if (err < 0) {
        return GRPC_ERROR;
      } else {
        return GRPC_ERROR_H2;
      }
  }
}

static iwrc _msg_slot_create(
  struct _request      *req,
  const struct iwn_val *msg,
  bool                  compressed,
  struct _msg_slot    **out) {
  iwrc rc = 0;
  struct _msg_slot *slot;
  struct iwpool *pool = 0;
  size_t mlen = 0;

  *out = 0;

  for (const struct iwn_val *v = msg; v; v = v->next) {
    if (v->len > req->client->spec.grpc.max_message_bytes) {
      return GRPC_ERROR_MSG_TOO_LARGE;
    }
    mlen += sizeof(*v) + v->len + sizeof(uint32_t) /* gRPC message length prefix */ + 1 /*compressed*/;
  }

  pool = iwpool_create_attach(req->pool, sizeof(*slot) + mlen);
  if (!pool) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }

  RCB(finish, slot = iwpool_alloc(sizeof(*slot), pool));
  slot->pool = pool;
  slot->next = 0;

  for (const struct iwn_val *v = msg; v; v = v->next) {
    struct iwn_val *nv;
    RCB(finish, nv = iwpool_calloc(sizeof(*nv), pool));
    nv->len = v->len + sizeof(uint32_t) /* gRPC message length prefix */ + 1 /* compressed */;
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
    memcpy(wp, v->buf, v->len);

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
      st->iov[0].iov_base
        = (char*) st->iov[0].iov_base + written;
      st->iov[0].iov_len -= written;
      written = 0;
    }
  }
}

static int _io_flush_writev(int fd, struct _io_writev_state *st, ssize_t *out_acc_written) {
  while (st->iovcnt > 0) {
    ssize_t ret = writev(fd, st->iov, st->iovcnt);
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

static inline bool _hive_rc_is_ok_for_io(int rch, struct hive_session *sess) {
  return rch == HIVE_OK || rch == HIVE_ERR_WOULDBLOCK;
}

static iwrc _fd_make_non_blocking(int fd) {
  int rci, flags;
  while ((flags = fcntl(fd, F_GETFL, 0)) == -1 && errno == EINTR) ;
  if (flags == -1) {
    return iwrc_set_errno(IW_ERROR_ERRNO, errno);
  }
  while ((rci = fcntl(fd, F_SETFL, flags | O_NONBLOCK)) == -1 && errno == EINTR) ;
  if (rci == -1) {
    return iwrc_set_errno(IW_ERROR_ERRNO, errno);
  }
  return 0;
}

static iwrc _deferred_callbacks_execute(struct iwn_grpc_client *client) {
  iwrc rc = 0;
  struct iwulist tasks = { .usize = sizeof(struct _deferred_callback) };
  pthread_mutex_lock(&client->mtx);
  rc = iwulist_copy(&client->deferred_callbacks, &tasks);
  if (rc) {
    pthread_mutex_unlock(&client->mtx);
    iwulist_destroy_keep(&tasks);
    return rc;
  }
  iwulist_reset(&client->deferred_callbacks);
  pthread_mutex_unlock(&client->mtx);
  for (int i = 0; i < tasks.num; ++i) {
    struct _deferred_callback *t = iwulist_get(&tasks, i);
    iwrc trc = t->execute(t);
    if (trc) {
      if (!rc) {
        rc = trc;
      }
      if (!(client->flags & IWN_GRPC_LOG_QUIET)) {
        iwlog_ecode_error2(rc, "grpc | API callback failed");
      }
    }
  }
  iwulist_destroy_keep(&tasks);
  return rc;
}

static int _deferred_callback_register(const struct _deferred_callback *cb) {
  struct iwn_grpc_client *client = cb->client;
  if (client->pa_closed) {
    return 0; // Client disposed
  }
  if (cb->immediate && !client->in_loop) {
    iwrc rc = cb->execute(cb);
    if (rc) {
      if (!(client->flags & IWN_GRPC_LOG_QUIET)) {
        iwlog_ecode_error2(rc, "grpc | API callback failed");
      }
    }
    return rc;
  } else {
    pthread_mutex_lock(&client->mtx);
    int rc = iwulist_push(&client->deferred_callbacks, cb);
    pthread_mutex_unlock(&client->mtx);
    return rc ? HIVE_ERR_NOMEM : 0;
  }
}

static void _client_ctx_init(struct iwn_grpc_client *client, struct iwn_grpc_client_ctx *ctx) {
  memset(ctx, 0, sizeof(*ctx));
  ctx->rc = client->rc;
  ctx->pa = client->pa;
  ctx->client = client;
  ctx->user_data = client->spec.user_data;
}

static void _rx_destroy(struct _rx *rx) {
  free(rx->body);
  memset(rx, 0, sizeof(*rx));
};

static void _rx_init(struct _rx *rx) {
  memset(rx, 0, sizeof(*rx));
  rx->state = _RX_HEADER;
}

static void _request_ctx_init(struct _request *req, struct iwn_grpc_req_ctx *ctx) {
  memset(ctx, 0, sizeof(*ctx));
  _client_ctx_init(req->client, &ctx->client_ctx);
  ctx->req_spec = req->spec;
  ctx->req_id = req->stream_id;
  ctx->rc = req->rc;
  ctx->error_explained = req->error_explained;
  ctx->data_encoding = req->data_encoding;
  ctx->output_data_encoding = req->output_data_encoding;
  ctx->impl = req;
}

static void _client_destroy(void *d) {
  struct iwn_grpc_client *client = d;

  if (client->spec.on_destroy) {
    struct iwn_grpc_client_ctx ctx;
    _client_ctx_init(client, &ctx);
    client->spec.on_destroy(&ctx);
  }

  iwulist_destroy_keep(&client->deferred_callbacks);
  iwhmap_destroy(client->requests_map);

  iwxstr_destroy(client->input_buf);
  pthread_mutex_destroy(&client->mtx);

  if (client->sess) {
    hive_session_free(client->sess);
  }
  if (client->hive_options) {
    hive_options_free(client->hive_options);
  }
  iwpool_destroy(client->pool);
}

IW_INLINE void _request_release_unref(struct _request *req) {
  if (req) {
    iwref_unref(&req->ref);
  }
}

static void _request_destroy(void *d) {
  struct _request *req = d;
  if (req->spec.on_destroy) {
    struct iwn_grpc_req_ctx ctx;
    _request_ctx_init(req, &ctx);
    req->spec.on_destroy(&ctx);
  }
  if (req->client) {
    iwref_unref(&req->client->ref);
  }
  _rx_destroy(&req->rx);
  iwpool_destroy(req->pool);
}

static iwrc _connect(struct iwn_grpc_client *client, int *out_fd) {
  iwrc rc = 0;
  *out_fd = 0;

  int fd = -1, rci;
  struct addrinfo *si = 0, *p = 0, hints = {
    .ai_family = PF_UNSPEC,
    .ai_socktype = SOCK_STREAM
  };

  char nbuf[IWNUMBUF_SIZE];
  snprintf(nbuf, sizeof(nbuf), "%d", client->url.port);
  char *port = nbuf;

  if ((client->flags & _FLAG_NO_NETWORK) == 0) {
    rci = getaddrinfo(client->url.host, port, &hints, &si);
    if (rci) {
      iwlog_ecode_error(GRPC_ERROR_PEER_CONNECT, "grpc | %s", gai_strerror(rci));
      return GRPC_ERROR_PEER_CONNECT;
    }
    for (p = si; p; p = p->ai_next) {
      char saddr[INET6_ADDRSTRLEN + 50];
      struct sockaddr *sa = p->ai_addr;
      void *addr = 0;

      if (sa->sa_family == AF_INET) {
        addr = &((struct sockaddr_in*) sa)->sin_addr;
      } else if (sa->sa_family == AF_INET6) {
        addr = &((struct sockaddr_in6*) sa)->sin6_addr;
      } else {
        iwlog_ecode_error(GRPC_ERROR_PEER_CONNECT, "grpc | Unsupported address family: 0x%x", (int) sa->sa_family);
        rc = GRPC_ERROR_PEER_CONNECT;
        goto finish;
      }

      if (!inet_ntop(p->ai_family, addr, saddr, sizeof(saddr))) {
        rc = iwrc_set_errno(IW_ERROR_ERRNO, errno);
        goto finish;
      }

      fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
      if (fd < 0) {
        iwlog_warn("grpc | Error opening socket %s:%s %s %s", client->url.host, port, saddr, strerror(errno));
        continue;
      }

#ifdef TCP_SYNCNT
      {                  // Apply 7s default timeout on Linux
        int syn_ret = 2; // Send a total of 3 SYN packets
        setsockopt(fd, IPPROTO_TCP, TCP_SYNCNT, &syn_ret, sizeof(syn_ret));
      }
#endif

      do {
        rci = connect(fd, p->ai_addr, p->ai_addrlen);
      } while (rci == -1 && errno == EINTR);

      if (rci == -1) {
        if (!(client->flags & IWN_GRPC_LOG_QUIET)) {
          iwlog_warn("grpc | Error connecting %s %s %s", client->url.host, saddr, strerror(errno));
        }
        close(fd), fd = -1;
        continue;
      }
      break;
    }
  } else {
    RCN(finish, fd = socket(AF_UNIX, SOCK_STREAM, 0));
    struct sockaddr_un saddr = {
      .sun_family = AF_UNIX
    };

    if (strlen(client->url.host) >= sizeof(saddr.sun_path)) {
      rc = IW_ERROR_INVALID_ARGS;
      iwlog_ecode_error(rc, "grpc | Unix socket path exceeds its maximum length: %zd", sizeof(saddr.sun_path) - 1);
      goto finish;
    }
    iwu_strncpy(saddr.sun_path, client->url.host, sizeof(saddr.sun_path) - 1);

    RCC(rc, finish, _fd_make_non_blocking(fd));

    do {
      rci = connect(fd, (void*) &saddr, sizeof(saddr));
    } while (rci == -1 && errno == EINTR);

    if (rci == -1) {
      if (!(client->flags & IWN_GRPC_LOG_QUIET)) {
        iwlog_warn("grpc | Error Unix socket connecting  %s %s", client->url.host, strerror(errno));
      }
      close(fd), fd = -1;
      goto finish;
    }
  }

  if (!INVALIDHANDLE(fd)) {
    *out_fd = fd;
  } else {
    rc = GRPC_ERROR_PEER_CONNECT;
  }

finish:
  if (si) {
    freeaddrinfo(si);
  }
  if (rc) {
    if (fd > -1) {
      close(fd);
    }
  } else { // Make socket non-blocking after connection established
    rc = _fd_make_non_blocking(fd);
  }
  return rc;
}

static iwrc _on_connected_deferred(const struct _deferred_callback *cb) {
  if (cb->client->spec.on_handshake) {
    struct iwn_grpc_client_ctx ctx;
    _client_ctx_init(cb->client, &ctx);
    return cb->client->spec.on_handshake(&ctx);
  } else {
    return 0;
  }
}

static iwrc _on_client_error_deferred(const struct _deferred_callback *cb) {
  struct iwn_grpc_client *client = cb->client;
  void (*on_error)(struct iwn_grpc_client_ctx*) = client->spec.on_error;
  if (on_error) {
    client->spec.on_error = 0;
    struct iwn_grpc_client_ctx ctx;
    _client_ctx_init(client, &ctx);
    on_error(&ctx);
  }
  return 0;
}

static iwrc _on_request_error_deferred(const struct _deferred_callback *cb) {
  struct iwn_grpc_req_ctx rctx;
  if (iwn_grpc_client_acquire_request_ctx(cb->client, cb->stream_id, &rctx)) {
    struct _request *req = rctx.impl;
    void (*on_error)(const struct iwn_grpc_req_ctx*) = req->spec.on_error;
    if (on_error) {
      req->spec.on_error = 0;
      on_error(&rctx);
    }
    iwn_grpc_client_release_request_ctx(&rctx);
  }
  return 0;
}

static iwrc _on_stream_close_deferred(const struct _deferred_callback *cb) {
  struct iwn_grpc_req_ctx rctx;
  if (iwn_grpc_client_acquire_request_ctx(cb->client, cb->stream_id, &rctx)) {
    struct _request *req = rctx.impl;

    if (cb->error_code && !req->rc) {
      req->rc = _hrc2rc(cb->error_code);
      rctx.rc = req->rc;
    }
    if (req->spec.on_closed) {
      req->spec.on_closed(&rctx);
    }
    void (*on_error)(const struct iwn_grpc_req_ctx*) = req->spec.on_error;
    if (req->rc && on_error) {
      req->spec.on_error = 0;
      on_error(&rctx);
    }

    pthread_mutex_lock(&cb->client->mtx);
    iwhmap_remove_u32(cb->client->requests_map, req->stream_id);
    pthread_mutex_unlock(&cb->client->mtx);
    iwref_unref(&req->ref);

    iwn_grpc_client_release_request_ctx(&rctx);
  }
  return 0;
}

static iwrc _on_goaway_deferred(const struct _deferred_callback *cb) {
  struct iwn_grpc_client *client = cb->client;
  // Runs at end of event loop so goaway_submitted check will be performed on next iteration.
  if (__sync_bool_compare_and_swap(&client->goaway_submitted, false, true)) {
    pthread_mutex_lock(&client->mtx);
    // Intentionally ignore error code below. Since correct delivering of GOAWAY is not critical.
    hive_submit_goaway_final(client->sess, HIVE_H2_CANCEL, 0, 0);
    pthread_mutex_unlock(&client->mtx);
    if (client->pa) {
      client->pa->arm(client->pa, IWN_POLLOUT);
    }
  }
  return 0;
}

static int _hcb_on_begin_headers(hive_session_t *session, uint32_t stream_id, void *user_data) {
  struct iwn_grpc_client *client = user_data;
  if (__sync_bool_compare_and_swap(&client->connected, false, true) && client->spec.on_handshake) {
    return _deferred_callback_register(&(struct _deferred_callback) {
      .client = client,
      .execute = _on_connected_deferred,
      .stream_id = stream_id,
    });
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
  iwrc rc = 0;
  struct iwn_grpc_client *client = user_data;
  struct _request *req = iwhmap_get_u32(client->requests_map, stream_id);
  if (!req) {
    return HIVE_ERR;
  }
  if (nb->len == IW_LLEN(":status") && strncmp((const char*) nb->data, ":status", nb->len) == 0) {
    req->http_status = iwatoi2((const char*) vb->data, vb->len);
  } else if (nb->len == IW_LLEN("grpc-status") && strncmp((const char*) nb->data, "grpc-status", nb->len) == 0) {
    req->grpc_status = iwatoi2((const char*) vb->data, vb->len);
  } else if (nb->len == IW_LLEN("grpc-message") && strncmp((const char*) nb->data, "grpc-message", nb->len) == 0) {
    size_t len;
    req->error_explained = iwpool_strndup2(req->pool, (const char*) vb->data, vb->len);
    // It is ok to leave partially changed error_explained in the case of error.
    iw_decode_percent_inplace(req->error_explained, vb->len, &len);
  } else if (nb->len == IW_LLEN("grpc-encoding") && strncmp((const char*) nb->data, "grpc-encoding", nb->len) == 0) {
    req->data_encoding = iwpool_strndup2(req->pool, (const char*) vb->data, vb->len);
  }
  return rc;
}

static int _hcb_on_headers_complete(
  hive_session_t *session,
  uint32_t        stream_id,
  uint8_t         flags,
  void           *user_data) {
  struct iwn_grpc_client *client = user_data;
  struct _request *req = iwhmap_get_u32(client->requests_map, stream_id);
  if (!req) {
    return HIVE_ERR;
  }
  if (!req->data_encoding) {
    req->data_encoding = "identity";
  }
  if (req->http_status != 200) {
    req->rc = GRPC_ERROR_H2_UNEXPECTED_STATUS;
    req->error_explained = iwpool_printf(req->pool, "Unexpected HTTP2 status code: %d Expected: 200", req->http_status);
  } else if (req->grpc_status) {
    req->rc = _grpc2rc(req->grpc_status);
  }
  if (req->rc && req->spec.on_error) {
    _deferred_callback_register(&(struct _deferred_callback) {
      .client = client,
      .execute = _on_request_error_deferred,
      .stream_id = stream_id,
    });
  }
  return 0;
}

static int _hcb_on_stream_close(
  hive_session_t *session,
  uint32_t        stream_id,
  uint32_t        error_code,
  void           *user_data) {
  return _deferred_callback_register(&(struct _deferred_callback) {
    .client = (struct iwn_grpc_client*) user_data,
    .execute = _on_stream_close_deferred,
    .error_code = error_code,
    .stream_id = stream_id,
  });
}

int _hcb_on_connection_error(
  hive_session_t *session,
  int             hive_err,
  uint32_t        h2_error_code,
  void           *user_data) {
  struct iwn_grpc_client *client = user_data;
  if (!client->rc) {
    client->rc = _hrc2rc(hive_err ? hive_err : h2_error_code);
    if (client->rc && client->spec.on_error) {
      return _deferred_callback_register(&(struct _deferred_callback) {
        .client = client,
        .error_code = client->rc,
        .execute = _on_client_error_deferred,
      });
    }
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
  struct iwn_grpc_client *client = user_data;
  __sync_bool_compare_and_swap(&client->goaway_submitted, false, true);
  return 0;
}

static int _hcb_on_data_chunk(
  hive_session_t *session,
  uint32_t        stream_id,
  const uint8_t  *data,
  size_t          len,
  uint8_t         flags,
  void           *user_data) {
  struct iwn_grpc_client *client = user_data;
  struct _request *req = iwhmap_get_u32(client->requests_map, stream_id);
  if (!req) {
    return HIVE_ERR;
  }
  struct _rx *rx = &req->rx;

  if (req->rc || !req->spec.on_message || rx->state == _RX_STOP) {
    return 0;
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
      if (rx->body_len > client->spec.grpc.max_message_bytes) {
        req->rc = GRPC_ERROR_MSG_TOO_LARGE;
        return HIVE_ERR;
      }
      rx->body_off = 0;
      free(rx->body);
      rx->body = 0;

      if (rx->body_len > 0) {
        rx->body = malloc(rx->body_len);
        if (!rx->body) {
          req->rc = iwrc_set_errno(IW_ERROR_ALLOC, errno);
          return HIVE_ERR_NOMEM;
        }
      }

      rx->state = _RX_BODY;
    }
    // BODY
    if (rx->state == _RX_BODY) {
      size_t need = rx->body_len - rx->body_off;
      size_t take = need < (len - off) ? need : (len - off);

      if (take > 0) {
        memcpy(rx->body + rx->body_off, data + off, take);
        rx->body_off += take;
        off += take;
      }

      if (rx->body_off < rx->body_len) {
        continue;
      }

      {
        struct iwn_grpc_req_message msg = {
          .msg = {
            .buf = (char*) rx->body,
            .len = rx->body_len,
          },
          .compressed = rx->compressed
        };
        _request_ctx_init(req, &msg.ctx);
        bool cont = true;
        req->spec.on_message(&msg, &cont);
        free(rx->body);
        memset(rx, 0, sizeof(*rx));
        if (!cont) {
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

static ssize_t _hcb_io_send(
  hive_session_t     *session,
  const struct iovec *iov_,
  int                 iovcnt,
  void               *user_data) {
  struct iwn_grpc_client *client = user_data;
  if (!client->pa || iovcnt < 1) {
    return 0;
  }

  struct iovec iov[iovcnt];
  for (int i = 0; i < iovcnt; ++i) {
    iov[i] = iov_[i];
  }

  ssize_t total = 0;
  int rci = _io_flush_writev(client->pa->fd, &(struct _io_writev_state) { iov, iovcnt }, &total);
  if (rci == -1) {
    return -1;
  }
  if (rci == 0) {
    client->io_wouldblock = true;
  }

  return total;
}

static iwrc _hive_pre_init(struct iwn_grpc_client *client) {
  iwrc rc = 0;
  struct hive_callbacks *cbs = &client->hive_callbacks;
  memset(cbs, 0, sizeof(*cbs));

  cbs->on_begin_headers = _hcb_on_begin_headers;
  cbs->on_header = _hcb_on_header;
  cbs->on_headers_complete = _hcb_on_headers_complete;
  cbs->on_connection_error = _hcb_on_connection_error;
  cbs->on_stream_close = _hcb_on_stream_close;
  cbs->on_goaway = _hcb_on_goaway;
  cbs->send = _hcb_io_send;
  cbs->on_data_chunk = _hcb_on_data_chunk;

  if (client->hive_options) {
    hive_options_free(client->hive_options);
  }

  RCB(finish, client->hive_options = hive_options_new());
  if (hive_options_set_enable_push(client->hive_options, 0) != HIVE_OK) {
    rc = GRPC_ERROR_CONFIG;
    iwlog_ecode_error3(rc);
    goto finish;
  }

finish:
  return rc;
}

static bool _client_want_write(struct iwn_grpc_client *client) {
  if (hive_session_want_write(client->sess, 1)) {
    return true;
  }
  struct iwhmap_iter it;
  iwhmap_iter_init(client->requests_map, &it);
  while (iwhmap_iter_next(&it)) {
    const struct _request *req = it.val;
    if (req->mslots || req->half_close_pending) {
      return true;
    }
  }
  return false;
}

static int64_t _on_poller_adapter_event_impl(struct iwn_poller_adapter *pa, void *user_data, uint32_t events) {
  struct iwn_grpc_client *client = user_data;
  if (client->pa != pa) {
    client->pa = pa;
  }

  iwrc rc = 0;
  int64_t ret = 0;
  int hrc = HIVE_OK;
  uint8_t buf[8192];
  struct hive_session *sess = client->sess;

  pthread_mutex_lock(&client->mtx);
  client->in_loop = true;

  if (IW_UNLIKELY(hive_session_closed(sess))) {
    client->in_loop = false;
    pthread_mutex_unlock(&client->mtx);
    return -1;
  }

  client->io_wouldblock = false;
  while (hrc == HIVE_OK && !client->io_wouldblock && _client_want_write(client)) {
    hrc = hive_session_send(sess);
  }
  if (!_hive_rc_is_ok_for_io(hrc, sess)) {
    goto unlock;
  }

  hrc = HIVE_OK;
  while (iwxstr_len(client->input_buf) && hive_session_want_read(sess)) {
    uint8_t *buf = (void*) iwxstr_ptr(client->input_buf);
    ssize_t consumed = hive_session_recv(sess, buf, iwxstr_len(client->input_buf));
    if (consumed < 0) {
      ret = -1;
      hrc = hive_session_last_error(sess);
      goto unlock;
    }
    iwxstr_shift(client->input_buf, consumed);
  }

  // Drain input fd buffer completelly in EPOLLET polling mode
  client->io_wouldblock = false;
  while (hive_session_want_read(sess)) {
    ssize_t n = recv(pa->fd, buf, sizeof(buf), 0);
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      } else if (errno == EWOULDBLOCK || errno == EAGAIN) {
        client->io_wouldblock = true;
        break;
      } else {
        rc = iwrc_set_errno(IW_ERROR_IO_ERRNO, errno);
        ret = -1;
        goto unlock;
      }
    } else if (n == 0) {
      if (!client->rc) {
        client->rc = GRPC_ERROR_UNAVAILABLE;
      }
      ret = -1;
      break;
    }
    ssize_t consumed = hive_session_recv(sess, buf, n);
    if (consumed < 0) {
      ret = -1;
      hrc = hive_session_last_error(sess);
      goto unlock;
    } else if (consumed < n) {
      RCC(rc, unlock, iwxstr_cat(client->input_buf, buf + consumed, n - consumed));
    }
  }

  // Drain input fd buffer completelly in EPOLLET polling mode
  client->io_wouldblock = false;
  while (!client->io_wouldblock) {
    ssize_t n = recv(pa->fd, buf, sizeof(buf), 0);
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      } else if (errno == EWOULDBLOCK || errno == EAGAIN) {
        client->io_wouldblock = true;
        break;
      } else {
        rc = iwrc_set_errno(IW_ERROR_IO_ERRNO, errno);
        ret = -1;
        goto unlock;
      }
    } else if (n == 0) {
      if (!client->rc) {
        client->rc = GRPC_ERROR_UNAVAILABLE;
      }
      ret = -1;
      break;
    }
    RCC(rc, unlock, iwxstr_cat(client->input_buf, buf, n));
  }

  if (hive_session_want_read(sess)) {
    ret |= IWN_POLLIN;
  }
  if (_client_want_write(client)) {
    ret |= IWN_POLLOUT;
  } else if (client->goaway_submitted && !client->pa->has_pending_write_bytes(client->pa)) {
    // Nothing to write, so we may close socket fd
    ret = -1;
  }

unlock:
  client->in_loop = false;
  pthread_mutex_unlock(&client->mtx);

  if (!rc && !_hive_rc_is_ok_for_io(hrc, sess)) {
    rc = _hrc2rc(hrc);
  }

  if (rc) {
    if (ret != -1) {
      ret = -1;
    }
    if (!client->rc) {
      client->rc = rc;
      if (client->spec.on_error) {
        _deferred_callback_register(&(struct _deferred_callback) {
          .client = client,
          .execute = _on_client_error_deferred,
          .error_code = rc,
        });
      }
    }
    if (!(client->spec.flags & IWN_GRPC_LOG_QUIET)) {
      iwlog_ecode_error3(rc);
    }
  }

  return ret;
}

static int64_t _on_poller_adapter_event(struct iwn_poller_adapter *pa, void *user_data, uint32_t events) {
  struct iwn_grpc_client *client = user_data;
  int64_t ret = _on_poller_adapter_event_impl(pa, user_data, events);
  iwrc rc = _deferred_callbacks_execute(client);
  if (rc) {
    ret = -1;
  }
  return ret;
}

static void _on_poller_adapter_dispose(struct iwn_poller_adapter *pa, void *user_data) {
  struct iwn_grpc_client *client = user_data;
  client->pa_closed = true;

  struct iwulist rlist = { .usize = sizeof(struct _request*) };
  pthread_mutex_lock(&client->mtx);
  struct iwhmap_iter it;
  iwhmap_iter_init(client->requests_map, &it);
  while (iwhmap_iter_next(&it)) {
    struct _request *req = (struct _request*) it.val;
    iwref_ref(&req->ref);
    iwulist_push(&rlist, &req);
  }
  iwhmap_clear(client->requests_map);
  pthread_mutex_unlock(&client->mtx);

  for (size_t i = 0; i < rlist.num; ++i) {
    struct _request *req = *(struct _request**) iwulist_get(&rlist, i);
    if (req->spec.on_closed) {
      struct iwn_grpc_req_ctx rctx;
      if (!req->rc) {
        req->rc = client->rc ? client->rc : GRPC_ERROR_UNAVAILABLE;
      }
      _request_ctx_init(req, &rctx);
      req->spec.on_closed(&rctx);
    }
  }

  for (size_t i = 0; i < rlist.num; ++i) {
    struct _request *req = *(struct _request**) iwulist_get(&rlist, i);
    iwref_unref(&req->ref);
    iwref_unref(&req->ref); // release final ref
  }

  iwulist_destroy_keep(&rlist);

  if (client->spec.on_closed) {
    struct iwn_grpc_client_ctx ctx;
    _client_ctx_init(client, &ctx);
    client->spec.on_closed(&ctx);
  }

  client->pa = 0;
  iwref_unref(&client->ref);
}

static iwrc _client_connect(struct iwn_grpc_client *client) {
  iwrc rc = 0;

  iwxstr_clear(client->input_buf);

  if (client->sess) {
    hive_session_free(client->sess);
    client->sess = 0;
  }

  RCC(rc, finish, _connect(client, &client->fd));

  client->sess = hive_session_client_new(0, client->hive_options, &client->hive_callbacks, client);
  if (!client->sess) {
    rc = GRPC_ERROR;
    iwlog_ecode_error2(rc, "grpc | Hive session initialization failed");
    goto finish;
  }

  iwref_ref(&client->ref);

  if (client->flags & _FLAG_SECURE) {
    RCC(rc, finish, iwn_brssl_client_poller_adapter(&(struct iwn_brssl_client_poller_adapter_spec) {
      .poller = client->poller,
      .host = client->url.host,
      .alpn_protocol_names = "h2", //< Only HTTP/2 is supported and allowed
      .on_event = _on_poller_adapter_event,
      .on_dispose = _on_poller_adapter_dispose,
      .user_data = client,
      .timeout_sec = client->spec.inactivity_timeout_sec,
      .events = IWN_POLLOUT,
      .events_mod = IWN_POLLET,
      .fd = client->fd,
      .verify_peer = client->flags & IWN_GRPC_TLS_VERIFY_PEER,
      .verify_host = client->flags & IWN_GRPC_TLS_VERIFY_HOST,
    }));
  } else {
    RCC(rc, finish, iwn_direct_poller_adapter(
          client->poller, client->fd,
          _on_poller_adapter_event,
          _on_poller_adapter_dispose,
          client, IWN_POLLOUT, IWN_POLLET,
          client->spec.inactivity_timeout_sec));
  }

  iwref_ref(&client->ref); // Will unref in _on_poller_adapter_dispose

finish:
  if (rc) {
    if (client->fd > -1) {
      shutdown(client->fd, SHUT_RDWR);
      close(client->fd);
      client->fd = -1;
    }
  }
  iwref_unref(&client->ref);
  return rc;
}

iwrc iwn_grpc_client_open(const struct iwn_grpc_client_spec *spec_, struct iwn_grpc_client **out_client) {
  iwrc rc = 0;
  if (!spec_ || !out_client || !spec_->poller || !spec_->url) {
    return IW_ERROR_INVALID_ARGS;
  }
  *out_client = 0;

  rc = iwn_grpc_init();
  RCRET(rc);

  struct iwn_grpc_client *client = 0;
  struct iwpool *pool = iwpool_create_empty();
  RCRA(pool);

  RCB(finish, client = iwpool_calloc(sizeof(*client), pool));
  client->pool = pool;
  client->poller = spec_->poller;
  client->flags = spec_->flags;
  client->fd = -1;
  client->spec = *spec_;

  if (!client->spec.grpc.max_message_bytes) {
    client->spec.grpc.max_message_bytes = 1024 * 1024; // 1Mb
  }

  pthread_mutexattr_t attr;
  pthread_mutexattr_init(&attr);
  pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
  pthread_mutex_init(&client->mtx, &attr);
  pthread_mutexattr_destroy(&attr);

  RCC(rc, finish, iwulist_init(&client->deferred_callbacks, 8, sizeof(struct _deferred_callback)));
  RCB(finish, client->input_buf = iwxstr_create_empty());

  iwref_init(&client->ref, client, _client_destroy);
  RCB(finish, client->spec.url = iwpool_strdup2(pool, client->spec.url));
  if (client->spec.authority) {
    RCB(finish, client->spec.authority = iwpool_strdup2(pool, client->spec.authority));
  }
  RCB(finish, client->requests_map = iwhmap_create_u32(0));

  char *urlbuf = iwpool_strdup2(pool, client->spec.url);
  RCB(finish, urlbuf);

  if (iwn_url_parse(&client->url, urlbuf) == -1) {
    iwlog_error("grpc | Failed to parse url: %s", client->spec.url);
    rc = IW_ERROR_INVALID_ARGS;
    goto finish;
  }

  client->flags |= _FLAG_SECURE;

  if (client->url.scheme) {
    if (strcmp("grpc+plaintext", client->url.scheme) == 0) {
      client->flags &= ~_FLAG_SECURE;
    } else if (strcmp("grpc+socket", client->url.scheme) == 0) {
      client->flags &= ~_FLAG_SECURE;
      client->flags |= _FLAG_NO_NETWORK;
      if (client->url.host == client->url.path - 1) {
        *(client->url.path - 1) = '/';   // WARNING: Dependent on iwn_url_parse implementation
      }
    }
  }

  if (client->url.port < 1) {
    if (client->flags & _FLAG_SECURE) {
      client->url.port = 443;
    } else {
      client->url.port = 80;
    }
  }

  if (!client->spec.authority) {
    RCB(finish, client->spec.authority = iwpool_printf(pool, "%s:%d", client->url.host, client->url.port));
  }

  if (!client->spec.user_agent) {
    client->spec.user_agent = "iwn-grpc-client/1";
  } else {
    RCB(finish, client->spec.user_agent = iwpool_strdup2(pool, client->spec.user_agent));
  }

  if (!client->spec.grpc.accept_encoding) {
    client->spec.grpc.accept_encoding = "identity";
  } else {
    RCB(finish, client->spec.grpc.accept_encoding = iwpool_strdup2(pool, client->spec.grpc.accept_encoding));
  }

  if (client->spec.authorization) {
    RCB(finish, client->spec.authorization = iwpool_strdup2(pool, client->spec.authorization))
  }

  RCC(rc, finish, _hive_pre_init(client));
  rc = _client_connect(client);

finish:
  if (rc) {
    if (!client) {
      iwpool_destroy(pool);
    } else {
      client->spec.on_destroy = 0;
      _client_destroy(client);
    }
  } else {
    *out_client = client;
  }
  return rc;
}

bool iwn_grpc_client_close(struct iwn_grpc_client *client) {
  if (!client) {
    return false;
  }
  if (!__sync_bool_compare_and_swap(&client->closed_by_api, false, true)) {
    return false;
  }
  _deferred_callback_register(&(struct _deferred_callback) {
    .client = client,
    .execute = _on_goaway_deferred,
    .immediate = true,
  });
  iwref_unref(&client->ref);
  return true;
}

static struct _request* _request_acquire_ref(struct iwn_grpc_client *client, uint32_t req_id) {
  struct _request *req = 0;
  pthread_mutex_lock(&client->mtx);
  req = iwhmap_get_u32(client->requests_map, req_id);
  if (req) {
    iwref_ref(&req->ref);
  }
  pthread_mutex_unlock(&client->mtx);
  return req;
}

static iwrc _on_messages_sent_deferred(const struct _deferred_callback *cb) {
  struct iwn_grpc_req_ctx rctx;
  if (iwn_grpc_client_acquire_request_ctx(cb->client, cb->stream_id, &rctx)) {
    struct _request *req = rctx.impl;
    if (req->spec.on_outgoing_messages_queue_drained) {
      req->spec.on_outgoing_messages_queue_drained(&rctx);
    }
    iwn_grpc_client_release_request_ctx(&rctx);
  }
  return 0;
}

static iwrc _on_request_close_deferred(const struct _deferred_callback *cb) {
  struct iwn_grpc_req_ctx rctx;
  if (iwn_grpc_client_acquire_request_ctx(cb->client, cb->stream_id, &rctx)) {
    struct _request *req = rctx.impl;
    if (req->spec.on_closed) {
      req->spec.on_closed(&rctx);
    }
    pthread_mutex_lock(&req->client->mtx);
    hive_submit_rst_stream(req->client->sess, rctx.req_id, HIVE_H2_CANCEL);
    iwhmap_remove_u32(req->client->requests_map, req->stream_id);
    pthread_mutex_unlock(&req->client->mtx);
    if (req->client->pa) {
      req->client->pa->arm(req->client->pa, IWN_POLLOUT);
    }
    iwref_unref(&req->ref);
    iwn_grpc_client_release_request_ctx(&rctx);
  }
  return 0;
}

static ssize_t _request_no_more_outgoing(struct _request *req, uint32_t *data_flags) {
  if (!req->client_streaming || req->half_close_pending) {
    *data_flags |= HIVE_DATA_FLAG_EOF;
    req->half_close_pending = false;
    return 0;
  }
  return HIVE_ERR_WOULDBLOCK;
}

static ssize_t _request_msg_read_callback(
  hive_session_t     *session,
  uint32_t            stream_id,
  uint8_t           **buf,
  size_t              length,
  uint32_t           *data_flags,
  hive_data_source_t *source,
  void               *user_data) {
  (void) user_data;
  struct _request *req = source ? source->ptr : 0;
  if (!req) {
    return HIVE_ERR;
  }

  struct iwn_val *v = 0;
  if (!req->mslots) {
    return _request_no_more_outgoing(req, data_flags);
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
    if (req->spec.on_outgoing_messages_queue_drained) {
      _deferred_callback_register(&(struct _deferred_callback) {
        .client = req->client,
        .stream_id = req->stream_id,
        .execute = _on_messages_sent_deferred,
      });
    }
    return _request_no_more_outgoing(req, data_flags);
    ;
  }

  uint8_t *ptr = (uint8_t*) v->buf + v->cnt;
  ssize_t m = v->len - v->cnt;
  ssize_t n = MIN(m, length);
  v->cnt += n;

  if (v->cnt < v->len || v->next || req->mslots->next) {
    *data_flags = *data_flags | HIVE_DATA_FLAG_NO_COPY;
    *buf = ptr;
  } else {
    struct _msg_slot *m = req->mslots;
    req->mslots = m->next;
    memcpy(*buf, ptr, n);
    _msg_slot_destroy(m);
    if (!req->mslots) {
      if (!req->client_streaming || req->half_close_pending) {
        *data_flags |= HIVE_DATA_FLAG_EOF;
        req->half_close_pending = false;
      }
      if (req->spec.on_outgoing_messages_queue_drained) {
        _deferred_callback_register(&(struct _deferred_callback) {
          .client = req->client,
          .stream_id = req->stream_id,
          .execute = _on_messages_sent_deferred,
        });
      }
    }
  }
  return n;
}

iwrc iwn_grpc_client_request_open(
  const struct iwn_grpc_req_spec *spec_,
  struct iwn_val                 *msg,
  const char                     *encoding,
  uint32_t                       *out_req_id) {
  if (!spec_ || !spec_->client || !spec_->path) {
    return IW_ERROR_INVALID_ARGS;
  }

  if (!msg && !spec_->client_streaming) {
    return IW_ERROR_INVALID_ARGS;
  }

  if (encoding && strcmp(encoding, "identity") == 0) {
    encoding = 0;
  }

  iwrc rc = 0;
  struct _request *req = 0;
  struct iwn_grpc_client *client = spec_->client;
  struct hive_data_source ds = {
    .read_callback = _request_msg_read_callback,
  };
  char grpc_timeout[64];

  struct iwpool *pool = iwpool_create_empty();
  if (!pool) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  RCB(finish, req = iwpool_calloc(sizeof(*req), pool));

  req->pool = pool;
  req->client = spec_->client;
  req->client_streaming = spec_->client_streaming;
  iwref_ref(&req->client->ref);
  iwref_init(&req->ref, req, _request_destroy);
  memcpy(&req->spec, spec_, sizeof(*spec_));

  if (encoding) {
    RCB(finish, req->output_data_encoding = iwpool_strdup2(pool, encoding));
  }
  RCB(finish, req->spec.path = iwpool_strdup2(pool, spec_->path));

  if (msg) {
    RCC(rc, finish, _msg_slot_create(req, msg, encoding != 0, &req->mslots));
  }

  ds.ptr = req;

  size_t n = 0;
  struct hive_nv headers[11] = { 0 };
  _hive_nv_set(&headers[n++], ":method", "POST", 0);
  if (client->flags & _FLAG_SECURE) {
    _hive_nv_set(&headers[n++], ":scheme", "https", 0);
  } else {
    _hive_nv_set(&headers[n++], ":scheme", "http", 0);
  }
  _hive_nv_set(&headers[n++], ":path", req->spec.path, 0);
  _hive_nv_set(&headers[n++], ":authority", client->spec.authority, 0);
  // gRPC specific headers
  _hive_nv_set(&headers[n++], "te", "trailers", 0);
  _hive_nv_set(&headers[n++], "content-type", "application/grpc+proto", 0);
  if (client->spec.grpc.timeout_sec) {
    snprintf(grpc_timeout, sizeof(grpc_timeout), "%uS", client->spec.grpc.timeout_sec);
    _hive_nv_set(&headers[n++], "grpc-timeout", grpc_timeout, 0);
  } else {
    _hive_nv_set(&headers[n++], "grpc-timeout", "30S", 0);
  }
  if (client->spec.grpc.accept_encoding) {
    _hive_nv_set(&headers[n++], "grpc-accept-encoding", client->spec.grpc.accept_encoding, 0);
  } else {
    _hive_nv_set(&headers[n++], "grpc-accept-encoding", "identity", 0);
  }
  if (encoding) {
    _hive_nv_set(&headers[n++], "grpc-encoding", encoding, 0);
  } else {
    _hive_nv_set(&headers[n++], "grpc-encoding", "identity", 0);
  }
  _hive_nv_set(&headers[n++], "user-agent", client->spec.user_agent, 0);
  if (client->spec.authorization) {
    _hive_nv_set(&headers[n++], "authorization", client->spec.authorization, HIVE_NV_FLAG_NO_INDEX);
  }

  pthread_mutex_lock(&client->mtx);
  rc = _hrc2rc(hive_submit_request(client->sess, headers, n, &ds, &req->stream_id));
  if (!rc) {
    rc = iwhmap_put_u32(client->requests_map, req->stream_id, req);
    if (rc) {
      hive_submit_rst_stream(client->sess, req->stream_id, HIVE_H2_CANCEL);
    }
  }
  pthread_mutex_unlock(&client->mtx);

  if (!rc && client->pa) {
    rc = client->pa->arm(client->pa, IWN_POLLOUT);
  }

finish:
  if (rc) {
    if (req) {
      req->rc = rc;
      _request_destroy(req);
    } else {
      iwpool_destroy(pool);
    }
  } else {
    if (out_req_id) {
      *out_req_id = req->stream_id;
    }
  }
  return rc;
}

struct iwn_grpc_req_ctx* iwn_grpc_client_acquire_request_ctx(
  struct iwn_grpc_client  *client,
  uint32_t                 req_id,
  struct iwn_grpc_req_ctx *out_ctx) {
  memset(out_ctx, 0, sizeof(*out_ctx));
  struct _request *req = _request_acquire_ref(client, req_id);
  if (!req) {
    return 0;
  }
  _request_ctx_init(req, out_ctx);
  out_ctx->impl = req;
  return out_ctx;
}

void iwn_grpc_client_release_request_ctx(struct iwn_grpc_req_ctx *rctx) {
  _request_release_unref(rctx->impl);
}

void iwn_grpc_client_request_close(struct iwn_grpc_req_ctx *rctx) {
  struct _request *req = rctx->impl;
  if (__sync_bool_compare_and_swap(&req->close_pending, false, true)) {
    _deferred_callback_register(&(struct _deferred_callback) {
      .client = req->client,
      .stream_id = req->stream_id,
      .execute = _on_request_close_deferred,
      .immediate = true,
    });
  }
}

iwrc iwn_grpc_client_stream_next_message(struct iwn_grpc_req_ctx *rctx, struct iwn_val *msg, bool stop_streaming) {
  if (!rctx || !rctx->impl) {
    return IW_ERROR_INVALID_ARGS;
  }
  iwrc rc = 0;
  struct _request *req = rctx->impl;
  struct iwn_grpc_client *client = req->client;
  assert(req);

  pthread_mutex_lock(&client->mtx);
  int hst = hive_stream_get_state(client->sess, req->stream_id);
  if (!req->client_streaming || _hive_is_stream_closed(hst)) {
    pthread_mutex_unlock(&client->mtx);
    return GRPC_ERROR_STREAM_CLOSED;
  }

  if (msg) {
    struct _msg_slot *ns;
    RCC(rc, finish, _msg_slot_create(req, msg, req->output_data_encoding != 0, &ns));
    struct _msg_slot *rs = req->mslots;
    if (rs) {
      while (rs->next) {
        rs = rs->next;
      }
      rs->next = ns;
    } else {
      req->mslots = ns;
    }
  }

  req->client_streaming = !stop_streaming;
  req->half_close_pending = stop_streaming;

finish:
  pthread_mutex_unlock(&client->mtx);
  if (!rc) {
    if (!client->pa) {
      rc = GRPC_ERROR_STREAM_CLOSED;
    } else if (client->pa) {
      rc = client->pa->arm(client->pa, IWN_POLLOUT);
    }
  }
  return rc;
}

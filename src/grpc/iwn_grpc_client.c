#include "iwn_grpc_client.h"
#include "iwn_url.h"
#include "ssl/iwn_brssl_poller_adapter.h"
#include "poller/iwn_direct_poller_adapter.h"

#include <iowow/iwrefs.h>
#include <iowow/iwlog.h>
#include <iowow/iwpool.h>
#include <iowow/iwutils.h>
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
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#define _FLAG_SECURE     0x01U
#define _FLAG_NO_NETWORK 0x02U

enum _rx_state {
  _RX_HEADER,
  _RX_BODY,
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

struct _request {
  struct iwref_holder      ref;
  struct iwn_grpc_client  *client;
  struct iwn_grpc_req_spec spec;
  struct _rx    rx;
  uint32_t      stream_id;
  uint32_t      error_code;
  volatile bool close_pending;
};

struct _deferred_callback {
  struct iwn_grpc_client *client;
  iwrc     (*execute)(const struct _deferred_callback*);
  uint32_t stream_id;
  uint32_t error_code;
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
  struct iwxstr *output_buf;

  struct iwn_grpc_client_spec spec;
  struct iwn_url url;

  pthread_mutex_t mtx;
  struct iwhmap  *requests_map;
  struct iwulist  deferred_callbacks;

  int      fd;              ///< Connection file descriptor
  unsigned flags;

  bool io_wouldblock;
  volatile bool close_pending;
  volatile bool io_stop;
};

struct _io_writev_state {
  struct iovec *iov;
  int iovcnt;
};

static void _io_session_goaway(struct iwn_grpc_client *client) {
  if (client->sess) {
    pthread_mutex_lock(&client->mtx);
    hive_submit_goaway_final(client->sess, HIVE_H2_CANCEL, 0, 0);
    pthread_mutex_unlock(&client->mtx);
  }
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
  iwulist_copy(&client->deferred_callbacks, &tasks);
  pthread_mutex_unlock(&client->mtx);
  for (int i = 0; i < tasks.num; ++i) {
    struct _deferred_callback *t = iwulist_get(&tasks, i);
    rc = t->execute(t);
    if (rc) {
      iwlog_ecode_error2(rc, "grpc | Callback task failed");
      goto finish;
    }
  }
finish:
  iwulist_destroy_keep(&tasks);
  return rc;
}

static iwrc _deferred_callback_register(const struct _deferred_callback *cb) {
  iwrc rc = 0;
  struct iwn_grpc_client *client = cb->client;
  pthread_mutex_lock(&client->mtx);
  rc = iwulist_push(&client->deferred_callbacks, cb);
  pthread_mutex_unlock(&client->mtx);
  return rc;
}

static void iwn_grpc_client_ctx_init(struct iwn_grpc_client *client, struct iwn_grpc_client_ctx *ctx) {
  memset(ctx, 0, sizeof(*ctx));
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
  iwn_grpc_client_ctx_init(req->client, &ctx->client_ctx);
  ctx->req_spec = req->spec;
  ctx->req_id = req->stream_id;
}

static void _client_destroy(void *d) {
  struct iwn_grpc_client *client = d;

  _deferred_callbacks_execute(client);

  if (client->spec.on_destroy) {
    struct iwn_grpc_client_ctx ctx;
    iwn_grpc_client_ctx_init(client, &ctx);
    client->spec.on_destroy(&ctx);
  }

  iwulist_destroy_keep(&client->deferred_callbacks);
  iwhmap_destroy(client->requests_map);

  iwxstr_destroy(client->input_buf);
  iwxstr_destroy(client->output_buf);
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
  struct iwn_grpc_client *client = req->client;
  if (req->spec.on_destroy) {
    struct iwn_grpc_req_ctx ctx;
    _request_ctx_init(req, &ctx);
    req->spec.on_destroy(&ctx);
  }
  iwref_unref(&client->ref);
  free(req);
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
      } while (errno == EINTR);

      if (rci == -1) {
        if (!(client->flags & GRPC_LOG_QUIET)) {
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
    } while (errno == EINTR);

    if (rci == -1) {
      if (!(client->flags & GRPC_LOG_QUIET)) {
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

static int _hcb_on_begin_headers(hive_session_t *session, uint32_t stream_id, void *user_data) {
  return 0;
}

static int _hcb_on_header(
  hive_session_t *session,
  uint32_t        stream_id,
  hive_buf_t     *name,
  hive_buf_t     *value,
  uint8_t         flags,
  void           *user_data) {
  return 0;
}

static int _hcb_on_headers_complete(
  hive_session_t *session,
  uint32_t        stream_id,
  uint8_t         flags,
  void           *user_data) {
  return 0;
}

static int _hcb_on_data_chunk(
  hive_session_t *session,
  uint32_t        stream_id,
  const uint8_t  *data,
  size_t          len,
  uint8_t         flags,
  void           *user_data) {
  return 0;
}

static iwrc _hcb_on_stream_close_deferred(const struct _deferred_callback *cb) {
  struct iwn_grpc_req_ctx rctx;
  if (iwn_grpc_client_acquire_request_ctx(cb->client, cb->stream_id, &rctx)) {
    iwn_grpc_client_request_close(&rctx);
    iwn_grpc_client_release_request_ctx(&rctx);
  }
  return 0;
}

static int _hcb_on_stream_close(
  hive_session_t *session,
  uint32_t        stream_id,
  uint32_t        error_code,
  void           *user_data) {
  _deferred_callback_register(&(struct _deferred_callback) {
    (struct iwn_grpc_client*) user_data,
    _hcb_on_stream_close_deferred,
    stream_id,
    error_code
  });
  return 0;
}

static int _hcb_on_goaway(
  hive_session_t *session,
  uint32_t        last_stream_id,
  uint32_t        error_code,
  const uint8_t  *debug_data,
  size_t          debug_len,
  void           *user_data) {
  return 0;
}

int _hcb_on_connection_error(
  hive_session_t *session,
  int             hive_err,
  uint32_t        h2_error_code,
  void           *user_data) {
  return 0;
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
  cbs->on_data_chunk = _hcb_on_data_chunk;
  cbs->on_goaway = _hcb_on_goaway;
  cbs->on_connection_error = _hcb_on_connection_error;
  cbs->on_stream_close = _hcb_on_stream_close;
  cbs->send = _hcb_io_send;

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

static int64_t _on_poller_adapter_event_impl(struct iwn_poller_adapter *pa, void *user_data, uint32_t events) {
  struct iwn_grpc_client *client = user_data;
  if (client->pa != pa) {
    client->pa = pa;
  }
  if (client->io_stop) {
    return -1;
  }

  struct hive_session *sess = client->sess;
  iwrc rc = 0;
  int64_t ret = 0;
  int hrc = HIVE_OK;
  uint8_t buf[8192];

  pthread_mutex_lock(&client->mtx);

  if (IW_UNLIKELY(hive_session_closed(sess))) {
    pthread_mutex_unlock(&client->mtx);
    return -1;
  }

  client->io_wouldblock = false;
  while (hrc == HIVE_OK && !client->io_wouldblock && hive_session_want_write(sess)) {
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
        ret = -1;
        goto unlock;
      }
    } else if (n == 0) {
      break;
    }
    ssize_t consumed = hive_session_recv(sess, buf, n);
    if (consumed < 0) {
      ret = -1;
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
        ret = -1;
        goto unlock;
      }
    } else if (n == 0) {
      break;
    }
    RCC(rc, unlock, iwxstr_cat(client->input_buf, buf, n));
  }

  if (hive_session_want_read(sess)) {
    ret |= IWN_POLLIN;
  }
  if (hive_session_want_write(sess)) {
    ret |= IWN_POLLOUT;
  }

unlock:
  pthread_mutex_unlock(&client->mtx);

  if (ret != -1 && (rc || !_hive_rc_is_ok_for_io(hrc, sess))) {
    ret = -1;
    if (rc) {
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
  client->pa = 0;
  iwref_unref(&client->ref);
}

static iwrc _client_connect(struct iwn_grpc_client *client) {
  iwrc rc = 0;

  iwxstr_clear(client->input_buf);
  iwxstr_clear(client->output_buf);

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
      .on_event = _on_poller_adapter_event,
      .on_dispose = _on_poller_adapter_dispose,
      .user_data = client,
      .timeout_sec = client->spec.inactivity_timeout_sec,
      .events = IWN_POLLOUT,
      .events_mod = IWN_POLLET,
      .fd = client->fd,
      .verify_peer = client->flags & GRPC_TLS_VERIFY_PEER,
      .verify_host = client->flags & GRPC_TLS_VERIFY_HOST,
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
  client->fd = -1;
  client->spec = *spec_;

  if (!client->spec.grpc_defaults.max_message_bytes) {
    client->spec.grpc_defaults.max_message_bytes = 1024 * 1024; // 1Mb
  }

  pthread_mutexattr_t attr;
  pthread_mutexattr_init(&attr);
  pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
  pthread_mutex_init(&client->mtx, &attr);
  pthread_mutexattr_destroy(&attr);

  RCB(finish, client->input_buf = iwxstr_create_empty());
  RCB(finish, client->output_buf = iwxstr_create_empty());

  iwref_init(&client->ref, client, _client_destroy);
  RCB(finish, client->spec.url = iwpool_strdup2(pool, client->spec.url));
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
        *(client->url.path - 1) = '/';   // WARNING: Dependence of iwn_url_parse implementation
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

  _hive_pre_init(client);
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

void iwn_grpc_client_close(struct iwn_grpc_client *client) {
  if (__sync_bool_compare_and_swap(&client->close_pending, false, true)) {
    _io_session_goaway(client);
    iwref_unref(&client->ref);
  }
}

static struct _request* _request_acquire_ref(struct iwn_grpc_client *client, uint32_t req_id) {
  struct _request *req = 0;
  pthread_mutex_lock(&client->mtx);
  req = iwhmap_get_u32(client->requests_map, req_id);
  pthread_mutex_unlock(&client->mtx);
  if (req) {
    iwref_ref(&req->ref);
  }
  return req;
}

iwrc iwn_grpc_client_request_open(const struct iwn_grpc_req_spec *spec, struct iwn_val *msg, uint32_t *out_req_id) {
  iwrc rc = 0;
  // TODO:
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
    struct iwn_grpc_client *client = req->client;
    pthread_mutex_lock(&client->mtx);
    iwhmap_remove_u32(client->requests_map, req->stream_id);
    pthread_mutex_unlock(&client->mtx);
    iwref_unref(&req->ref);
  }
}

#include "iwnet.h"
#include "iwn_s2n_poller_adapter.h"

#include <s2n.h>

#include <iowow/iwlog.h>
#include <iowow/iwpool.h>

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

struct pa {
  struct iwn_poller_adapter     b;
  iwn_on_poller_adapter_event   on_event;
  iwn_on_poller_adapter_dispose on_dispose;
  struct iwpool     *pool;
  struct s2n_config *config;
  struct s2n_connection *conn;
  struct s2n_cert_chain_and_key *cak;
  pthread_mutex_t mtx;
  pthread_key_t   ready_fd_tl;
  bool negotiated;
  bool closed;
  bool need_read;     ///< Deliver `IWN_POLLIN` right after the handshake.
  bool write_pending; ///< s2n has buffered TLS records which are not flushed yet.
  bool tl_ready;      ///< `ready_fd_tl` key was created.
};

static pthread_once_t _s2n_init_once = PTHREAD_ONCE_INIT;
static iwrc _s2n_init_rc;

static void _s2n_init_fn(void) {
  if (s2n_init() != S2N_SUCCESS) {
    _s2n_init_rc = IW_ERROR_FAIL;
    iwlog_error("s2n | Library initialization failed: [%s] %s",
                s2n_strerror_name(s2n_errno), s2n_strerror(s2n_errno, "EN"));
    s2n_errno = S2N_ERR_T_OK;
  }
}

IW_INLINE iwrc _init(void) {
  pthread_once(&_s2n_init_once, _s2n_init_fn);
  return _s2n_init_rc;
}

static void _error(const char *op) {
  iwlog_error("s2n | %s failed: [%s] %s",
              op, s2n_strerror_name(s2n_errno), s2n_strerror(s2n_errno, "EN"));
  s2n_errno = S2N_ERR_T_OK;
}

IW_INLINE bool _is_blocked(void) {
  bool ret = s2n_error_get_type(s2n_errno) == S2N_ERR_T_BLOCKED;
  if (ret) {
    s2n_errno = S2N_ERR_T_OK;
  }
  return ret;
}

static char* _read_file(struct iwpool *pool, const char *path) {
  char *ret = 0;
  int fd = open(path, O_RDONLY);
  if (fd < 0) {
    return 0;
  }
  struct stat st;
  if (fstat(fd, &st) != 0 || st.st_size < 0) {
    close(fd);
    return 0;
  }
  size_t size = (size_t) st.st_size;
  ret = iwpool_alloc(size + 1, pool);
  if (!ret) {
    close(fd);
    return 0;
  }
  size_t off = 0;
  while (off < size) {
    ssize_t len = read(fd, ret + off, size - off);
    if (len < 0) {
      if (errno == EINTR) {
        continue;
      }
      close(fd);
      return 0;
    } else if (len == 0) {
      break;
    }
    off += len;
  }
  close(fd);
  ret[off] = '\0';
  return ret;
}

static char* _load_pem(struct iwpool *pool, const char *data, ssize_t len, bool in_buffer) {
  if (len < 0) {
    len = strlen(data);
  }
  if (in_buffer) {
    return iwpool_strndup2(pool, data, len);
  }
  return _read_file(pool, data);
}

IW_INLINE void _destroy(struct pa *a) {
  if (a->conn) {
    s2n_connection_free(a->conn);
  }
  if (a->config) {
    s2n_config_free(a->config);
  }
  if (a->cak) {
    s2n_cert_chain_and_key_free(a->cak);
  }
  if (a->tl_ready) {
    pthread_key_delete(a->ready_fd_tl);
  }
  pthread_mutex_destroy(&a->mtx);
  if (a->pool) {
    iwpool_destroy(a->pool);
  }
}

static void _on_dispose(const struct iwn_poller_task *t) {
  struct pa *a = t->user_data;
  if (a->on_dispose) {
    a->on_dispose((void*) a, a->b.user_data);
  }
  _destroy(a);
}

static ssize_t _read(struct iwn_poller_adapter *pa, uint8_t *data, size_t len) {
  struct pa *a = (void*) pa;
  if (!a->negotiated || a->closed) {
    errno = EAGAIN;
    return -1;
  }
  s2n_blocked_status blocked = S2N_NOT_BLOCKED;
  ssize_t ret = s2n_recv(a->conn, data, len, &blocked);
  if (ret < 0) {
    if (_is_blocked()) {
      errno = EAGAIN;
    } else {
      _error("read");
      errno = EIO;
    }
    return -1;
  }
  return ret;
}

static ssize_t _write(struct iwn_poller_adapter *pa, const uint8_t *data, size_t len) {
  struct pa *a = (void*) pa;
  if (!a->negotiated || a->closed) {
    errno = EAGAIN;
    return -1;
  }
  s2n_blocked_status blocked = S2N_NOT_BLOCKED;
  ssize_t ret = s2n_send(a->conn, data, len, &blocked);
  if (ret < 0) {
    if (_is_blocked()) {
      a->write_pending = blocked == S2N_BLOCKED_ON_WRITE;
      errno = EAGAIN;
    } else {
      _error("write");
      errno = EIO;
    }
    return -1;
  }
  // A partial write means TLS records are still buffered by s2n
  a->write_pending = (size_t) ret < len;
  return ret;
}

static void _has_pending_write_bytes_probe(struct iwn_poller *p, void *slot_user_data, void *fn_user_data) {
  struct pa *a = slot_user_data;
  bool *ret = fn_user_data;
  pthread_mutex_lock(&a->mtx);
  *ret = a->negotiated && !a->closed && a->write_pending;
  pthread_mutex_unlock(&a->mtx);
};

static bool _has_pending_write_bytes(struct iwn_poller_adapter *a) {
  bool ret = false;
  iwn_poller_probe(a->poller, a->fd, _has_pending_write_bytes_probe, &ret);
  return ret;
};

static void _arm_needed_probe(struct iwn_poller *p, void *slot_user_data, void *fn_user_data) {
  struct pa *a = slot_user_data;
  bool *ret = fn_user_data;
  *ret = pthread_getspecific(a->ready_fd_tl) != (void*) 1;
};

static bool _arm_needed(struct iwn_poller_adapter *a) {
  bool ret = false;
  iwn_poller_probe(a->poller, a->fd, _arm_needed_probe, &ret);
  return ret;
};

static iwrc _arm(struct iwn_poller_adapter *a, uint32_t events) {
  if (_arm_needed(a)) {
    return iwn_poller_arm_events(a->poller, a->fd, events);
  }
  return 0;
}

static const char* _get_protocol_name(struct iwn_poller_adapter *pa) {
  struct pa *a = (void*) pa;
  if (!a->negotiated) {
    return 0;
  }
  return s2n_get_application_protocol(a->conn);
}

/// Returns poll events needed to make progress when TLS layer waits for I/O,
/// or `-1` on error.
static int64_t _next_poll(struct pa *a) {
  if (a->closed) {
    return -1;
  }
  int64_t ret = IWN_POLLIN;
  if (a->write_pending) {
    ret |= IWN_POLLOUT;
  }
  return ret;
}

static int64_t _on_ready(const struct iwn_poller_task *t, uint32_t flags) {
  struct pa *a = t->user_data;
  int64_t nflags = -1;
  bool locked = false;

  pthread_setspecific(a->ready_fd_tl, (void*) 1);
  pthread_mutex_lock(&a->mtx), locked = true;

  if (a->closed) {
    goto finish;
  }

  if (!a->negotiated) {
    s2n_blocked_status blocked = S2N_NOT_BLOCKED;
    if (s2n_negotiate(a->conn, &blocked) != S2N_SUCCESS) {
      if (_is_blocked()) {
        nflags = blocked == S2N_BLOCKED_ON_WRITE ? IWN_POLLOUT : IWN_POLLIN;
      } else {
        _error("handshake");
        a->closed = true;
      }
      goto finish;
    }
    a->negotiated = true;
    a->need_read = true;
  }

  // Events requested by the consumer are returned to the poller
  int64_t requested = 0;

  bool write_delivered = false;
  if (flags & IWN_POLLOUT) {
    int64_t n = a->on_event((void*) a, a->b.user_data, IWN_POLLOUT);
    if (n == -1) {
      a->closed = true;
      goto finish;
    }
    requested |= n;
    write_delivered = true;
  }

  bool deliver_read = (flags & IWN_POLLIN) || a->need_read;
  a->need_read = false;
  uint32_t peeked = s2n_peek(a->conn);
  while (deliver_read && !a->closed) {
    int64_t n = a->on_event((void*) a, a->b.user_data, IWN_POLLIN);
    if (n == -1) {
      a->closed = true;
      goto finish;
    }
    requested |= n;
    // Data may be left decrypted by s2n in its internal record buffer
    uint32_t now = s2n_peek(a->conn);
    if (now == 0 || now >= peeked) {
      break;
    }
    peeked = now;
  }

  // s2n buffers outgoing records internally, so unlike the socket level there is
  // no backpressure which could signal the consumer to retry a delayed write.
  // Give it a write opportunity on every ready event.
  if (!write_delivered && !a->closed) {
    int64_t n = a->on_event((void*) a, a->b.user_data, IWN_POLLOUT);
    if (n == -1) {
      a->closed = true;
      goto finish;
    }
    requested |= n;
  }

  nflags = _next_poll(a);
  if (requested > 0 && nflags > 0) {
    nflags |= requested;
  }

finish:
  if (locked) {
    pthread_mutex_unlock(&a->mtx);
  }
  pthread_setspecific(a->ready_fd_tl, 0);
  return nflags;
}

static iwrc _adapter_init(struct pa *a) {
  a->b.read = _read;
  a->b.write = _write;
  a->b.arm = _arm;
  a->b.get_protocol_name = _get_protocol_name;
  a->b.has_pending_write_bytes = _has_pending_write_bytes;

  pthread_mutexattr_t attr;
  pthread_mutexattr_init(&attr);
  pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
  pthread_mutex_init(&a->mtx, &attr);
  pthread_mutexattr_destroy(&attr);

  if (pthread_key_create(&a->ready_fd_tl, 0) != 0) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  a->tl_ready = true;
  return 0;
}

static iwrc _alpn_set(struct pa *a, struct iwpool *pool, const char *alpn_protocol_names) {
  if (!alpn_protocol_names) {
    return 0;
  }
  const char **pnames = iwpool_split_string(pool, alpn_protocol_names, ",", true);
  if (!pnames) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  int num = 0;
  for (const char **pn = pnames; *pn; ++pn) {
    ++num;
  }
  if (num > 0 && s2n_config_set_protocol_preferences(a->config, pnames, num) != S2N_SUCCESS) {
    _error("ALPN setup");
    return IWN_TLS_ERROR_HANDSHAKE;
  }
  return 0;
}

iwrc iwn_s2n_server_poller_adapter(const struct iwn_tls_server_poller_adapter_spec *spec) {
  iwrc rc = 0;
  if (!spec->poller) {
    iwlog_ecode_error2(IW_ERROR_INVALID_ARGS, "No poller specified");
    return IW_ERROR_INVALID_ARGS;
  }
  if (!spec->on_event) {
    iwlog_ecode_error2(IW_ERROR_INVALID_ARGS, "No on_event specified");
    return IW_ERROR_INVALID_ARGS;
  }
  if (!spec->certs || !spec->private_key) {
    iwlog_ecode_error2(IW_ERROR_INVALID_ARGS, "No certs or private_key specified");
    return IW_ERROR_INVALID_ARGS;
  }
  RCRET(_init());

  struct iwpool *pool = iwpool_create_empty();
  if (!pool) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  struct pa *a = iwpool_calloc(sizeof(*a), pool);
  if (!a) {
    iwpool_destroy(pool);
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  a->pool = pool;
  a->b.fd = spec->fd;
  a->b.poller = spec->poller;
  a->b.user_data = spec->user_data;
  a->on_event = spec->on_event;
  a->on_dispose = spec->on_dispose;

  RCC(rc, finish, _adapter_init(a));

  char *certs = _load_pem(pool, spec->certs, spec->certs_len, spec->certs_in_buffer);
  if (!certs) {
    iwlog_ecode_error2(IWN_TLS_ERROR_CERT_DATA, "Unable to load server certificates");
    rc = IWN_TLS_ERROR_CERT_DATA;
    goto finish;
  }
  char *private_key = _load_pem(pool, spec->private_key, spec->private_key_len, spec->private_key_in_buffer);
  if (!private_key) {
    iwlog_ecode_error2(IWN_TLS_ERROR_PRIVKEY_DATA, "Unable to load server private key");
    rc = IWN_TLS_ERROR_PRIVKEY_DATA;
    goto finish;
  }

  a->config = s2n_config_new();
  if (!a->config) {
    _error("config allocation");
    rc = IW_ERROR_ALLOC;
    goto finish;
  }
  a->cak = s2n_cert_chain_and_key_new();
  if (!a->cak) {
    _error("certificate allocation");
    rc = IW_ERROR_ALLOC;
    goto finish;
  }
  if (s2n_cert_chain_and_key_load_pem(a->cak, certs, private_key) != S2N_SUCCESS) {
    _error("certificate loading");
    rc = IWN_TLS_ERROR_CERT_DATA;
    goto finish;
  }
  if (s2n_config_add_cert_chain_and_key_to_store(a->config, a->cak) != S2N_SUCCESS) {
    _error("certificate store setup");
    rc = IWN_TLS_ERROR_CERT_DATA;
    goto finish;
  }
  RCC(rc, finish, _alpn_set(a, pool, spec->alpn_protocol_names));

  a->conn = s2n_connection_new(S2N_SERVER);
  if (!a->conn) {
    _error("connection allocation");
    rc = IW_ERROR_ALLOC;
    goto finish;
  }
  // Never block the poller thread on error blinding delays
  if (  s2n_connection_set_blinding(a->conn, S2N_SELF_SERVICE_BLINDING) != S2N_SUCCESS
     || s2n_connection_set_config(a->conn, a->config) != S2N_SUCCESS
     || s2n_connection_set_fd(a->conn, spec->fd) != S2N_SUCCESS) {
    _error("connection setup");
    rc = IWN_TLS_ERROR_HANDSHAKE;
    goto finish;
  }

  rc = iwn_poller_add(&(struct iwn_poller_task) {
    .fd = spec->fd,
    .poller = spec->poller,
    .user_data = a,
    .on_ready = _on_ready,
    .on_dispose = _on_dispose,
    .timeout = spec->timeout_sec,
    .events = spec->events,
    .events_mod = spec->events_mod,
  });

finish:
  if (rc) {
    _destroy(a);
  }
  return rc;
}

static uint8_t _verify_host_ignore(const char *host_name, size_t host_name_len, void *data) {
  return 1;
}

iwrc iwn_s2n_client_poller_adapter(const struct iwn_tls_client_poller_adapter_spec *spec) {
  iwrc rc = 0;
  if (!spec->poller) {
    iwlog_ecode_error2(IW_ERROR_INVALID_ARGS, "No poller specified");
    return IW_ERROR_INVALID_ARGS;
  }
  if (!spec->on_event) {
    iwlog_ecode_error2(IW_ERROR_INVALID_ARGS, "No on_event specified");
    return IW_ERROR_INVALID_ARGS;
  }
  RCRET(_init());

  struct iwpool *pool = iwpool_create_empty();
  if (!pool) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  struct pa *a = iwpool_calloc(sizeof(*a), pool);
  if (!a) {
    iwpool_destroy(pool);
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  a->pool = pool;
  a->b.fd = spec->fd;
  a->b.poller = spec->poller;
  a->b.user_data = spec->user_data;
  a->on_event = spec->on_event;
  a->on_dispose = spec->on_dispose;

  RCC(rc, finish, _adapter_init(a));

  a->config = s2n_config_new();
  if (!a->config) {
    _error("config allocation");
    rc = IW_ERROR_ALLOC;
    goto finish;
  }

  if (!spec->verify_peer) {
    if (s2n_config_disable_x509_verification(a->config) != S2N_SUCCESS) {
      _error("X.509 verification setup");
      rc = IWN_TLS_ERROR_HANDSHAKE;
      goto finish;
    }
  } else {
    const char *cacerts = spec->cacerts_data;
    size_t cacerts_len = spec->cacerts_data_len;
    if (!cacerts || !cacerts_len) {
      cacerts = iwn_cacerts;
      cacerts_len = iwn_cacerts_len;
    }
    RCB(finish, cacerts = iwpool_strndup2(pool, cacerts, cacerts_len));
    if (s2n_config_add_pem_to_trust_store(a->config, cacerts) != S2N_SUCCESS) {
      _error("CA certificates loading");
      rc = IWN_TLS_ERROR_CERT_DATA;
      goto finish;
    }
    if (!spec->verify_host && s2n_config_set_verify_host_callback(a->config, _verify_host_ignore, 0) != S2N_SUCCESS) {
      _error("host verification setup");
      rc = IWN_TLS_ERROR_HANDSHAKE;
      goto finish;
    }
  }
  RCC(rc, finish, _alpn_set(a, pool, spec->alpn_protocol_names));

  a->conn = s2n_connection_new(S2N_CLIENT);
  if (!a->conn) {
    _error("connection allocation");
    rc = IW_ERROR_ALLOC;
    goto finish;
  }
  if (  s2n_connection_set_blinding(a->conn, S2N_SELF_SERVICE_BLINDING) != S2N_SUCCESS
     || s2n_connection_set_config(a->conn, a->config) != S2N_SUCCESS
     || s2n_connection_set_fd(a->conn, spec->fd) != S2N_SUCCESS) {
    _error("connection setup");
    rc = IWN_TLS_ERROR_HANDSHAKE;
    goto finish;
  }
  if (spec->host && s2n_set_server_name(a->conn, spec->host) != S2N_SUCCESS) {
    _error("server name setup");
    rc = IWN_TLS_ERROR_HANDSHAKE;
    goto finish;
  }

  rc = iwn_poller_add(&(struct iwn_poller_task) {
    .fd = spec->fd,
    .poller = spec->poller,
    .user_data = a,
    .on_ready = _on_ready,
    .on_dispose = _on_dispose,
    .timeout = spec->timeout_sec,
    .events = spec->events,
    .events_mod = spec->events_mod,
  });

finish:
  if (rc) {
    _destroy(a);
  }
  return rc;
}

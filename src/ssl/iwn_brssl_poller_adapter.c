#include "iwnet.h"
#include "iwn_brssl_poller_adapter.h"
#include "iwn_tls_config.h"

#include "bearssl/brssl.h"
#include <iowow/iwlog.h>
#include <iowow/iwpool.h>

#include <stdlib.h>
#include <errno.h>
#include <pthread.h>
#include <unistd.h>

#if defined(SO_NOSIGPIPE)
#include <sys/socket.h>
#endif

struct x509_client_context {
  const br_x509_class    *vtable;
  br_x509_minimal_context minimal;
  bool verifyhost;
  bool verifypeer;
};

struct pa {
  struct iwn_poller_adapter     b;
  iwn_on_poller_adapter_event   on_event;
  iwn_on_poller_adapter_dispose on_dispose;
  struct iwpool *pool;
  br_ssl_engine_context *eng;
  pthread_mutex_t mtx;
  union {
    struct  {
      br_ssl_client_context      cc;
      struct x509_client_context x509;
    } client;

    struct {
      br_ssl_server_context sc;
    } server;
  };

  /// TLS settings owned by the adapter, `0` when a shared config is borrowed.
  struct iwn_brssl_server_config *owned_server_config;
  struct iwn_brssl_client_config *owned_client_config;

  bool is_client;
  unsigned char iobuf[BR_SSL_BUFSIZE_BIDI];
};

static const char* _ecodefn(locale_t locale, uint32_t ecode) {
  if (ecode <= _BRS_ERROR_START || ecode >= _BRS_ERROR_END) {
    return 0;
  }
  switch (ecode) {
    case BRS_ERROR_INVALID_CASCERT_DATA:
      return "Invalid CA cetificates (BRS_ERROR_INVALID_CASCERT_DATA)";
    case BRS_ERROR_INVALID_PRIVKEY_DATA:
      return "Invalid private key data (BRS_ERROR_INVALID_PRIVKEY_DATA)";
  }
  return 0;
}

static void _init(void) {
  static bool _initialized = false;
  if (__sync_bool_compare_and_swap(&_initialized, false, true)) {
    iwlog_register_ecodefn(_ecodefn);
  }
}

static ssize_t _read(struct iwn_poller_adapter *pa, uint8_t *data, size_t len) {
  struct pa *a = (void*) pa;
  br_ssl_engine_context *cc = a->eng;
  size_t tor = len;
  while (tor > 0 && (br_ssl_engine_current_state(cc) & BR_SSL_RECVAPP)) {
    size_t blen;
    unsigned char *buf = br_ssl_engine_recvapp_buf(cc, &blen);
    if (blen > tor) {
      blen = tor;
    }
    memcpy(data, buf, blen);
    buf += blen;
    tor -= blen;
    br_ssl_engine_recvapp_ack(cc, blen);
  }
  if (tor == len) {
    errno = EAGAIN;
    return -1;
  } else {
    return len - tor;
  }
}

static ssize_t _write(struct iwn_poller_adapter *pa, const uint8_t *data, size_t len) {
  struct pa *a = (void*) pa;
  br_ssl_engine_context *cc = a->eng;
  size_t tow = len;

  while (tow > 0 && (br_ssl_engine_current_state(cc) & BR_SSL_SENDAPP)) {
    size_t blen;
    unsigned char *buf = br_ssl_engine_sendapp_buf(cc, &blen);
    if (blen > tow) {
      blen = tow;
    }
    memcpy(buf, data, blen);
    data += blen;
    tow -= blen;
    br_ssl_engine_sendapp_ack(cc, blen);
    br_ssl_engine_flush(cc, 0);
  }
  if (tow == len) {
    errno = EAGAIN;
    return -1;
  } else {
    return len - tow;
  }
}

IW_INLINE void _destroy(struct pa *a) {
  iwn_brssl_server_config_free(a->owned_server_config);
  iwn_brssl_client_config_free(a->owned_client_config);
  pthread_mutex_destroy(&a->mtx);
  iwpool_destroy(a->pool);
}

static void _on_dispose(const struct iwn_poller_task *t) {
  struct pa *a = t->user_data;
  if (a->on_dispose) {
    a->on_dispose((void*) a, a->b.user_data);
  }
  _destroy(a);
}

static int _write_fd(struct pa *a, const unsigned char *buf, size_t len) {
  while (1) {
#ifdef MSG_NOSIGNAL
    ssize_t wlen = send(a->b.fd, buf, len, MSG_NOSIGNAL);
#else
    ssize_t wlen = write(a->b.fd, buf, len);
#endif
    if (wlen < 0 && errno == EINTR) {
      continue;
    }
    return (int) wlen;
  }
}

static int _read_fd(struct pa *a, unsigned char *buf, size_t len) {
  while (1) {
    ssize_t rlen = read(a->b.fd, buf, len);
    if (rlen < 0 && errno == EINTR) {
      continue;
    }
    return (int) rlen;
  }
}

static inline int64_t _next_poll(br_ssl_engine_context *cc) {
  int64_t ret = 0;
  unsigned cs = br_ssl_engine_current_state(cc);
  if (cs & BR_SSL_CLOSED) {
    return -1;
  }
  if (cs & BR_SSL_RECVREC) {
    ret |= IWN_POLLIN;
  }
  if (cs & BR_SSL_SENDREC) {
    ret |= IWN_POLLOUT;
  }
  if (ret == 0) {
    ret |= IWN_POLLIN;
  }
  return ret;
}

static bool _has_pending_write_bytes(struct iwn_poller_adapter *pa) {
  struct pa *a = (void*) pa;
  br_ssl_engine_context *cc = a->eng;
  pthread_mutex_lock(&a->mtx);
  bool ret = (br_ssl_engine_current_state(cc) & BR_SSL_SENDREC) != 0;
  pthread_mutex_unlock(&a->mtx);
  return ret;
}

static iwrc _arm(struct iwn_poller_adapter *a, uint32_t events) {
  // When called from the adapter event callback the poller merges the request into
  // the events armed after the callback returns, so it is never lost.
  return iwn_poller_arm_events(a->poller, a->fd, events);
}

static const char* _get_protocol_name(struct iwn_poller_adapter *pa) {
  struct pa *a = (void*) pa;
  br_ssl_engine_context *cc = a->eng;
  return br_ssl_engine_get_selected_protocol(cc);
}

static int64_t _on_ready(const struct iwn_poller_task *t, uint32_t flags) {
  struct pa *a = t->user_data;
  br_ssl_engine_context *cc = a->eng;
  bool write_done, read_done;
  bool locked = false;
  int64_t nflags;

  do {
    nflags = -1;
    pthread_mutex_lock(&a->mtx), locked = true;

    if (br_ssl_engine_current_state(cc) == BR_SSL_CLOSED) {
      goto finish;
    }

    write_done = !(br_ssl_engine_current_state(cc) & BR_SSL_SENDREC);
    while (br_ssl_engine_current_state(cc) & BR_SSL_SENDREC) {
      size_t len;
      unsigned char *buf = br_ssl_engine_sendrec_buf(cc, &len);
      int wlen = _write_fd(a, buf, len);
      if (wlen == 0) {
        goto finish;
      } else if (wlen < 0) {
        if (errno == EWOULDBLOCK || errno == EAGAIN) {
          write_done = true;
          break;
        } else {
          goto finish;
        }
      }
      br_ssl_engine_sendrec_ack(cc, wlen);
    }

    read_done = !(br_ssl_engine_current_state(cc) & BR_SSL_RECVREC);
    while (br_ssl_engine_current_state(cc) & BR_SSL_RECVREC) {
      size_t len;
      unsigned char *buf = br_ssl_engine_recvrec_buf(cc, &len);
      int rlen = _read_fd(a, buf, len);
      if (rlen == 0) {
        goto finish;
      } else if (rlen < 0) {
        if (errno == EWOULDBLOCK || errno == EAGAIN) {
          read_done = true;
          break;
        } else {
          goto finish;
        }
      }
      br_ssl_engine_recvrec_ack(cc, rlen);
    }

    while (br_ssl_engine_current_state(cc) & BR_SSL_SENDAPP) {
      int64_t n = a->on_event((void*) a, a->b.user_data, IWN_POLLOUT);
      if (n == -1) {
        goto finish;
      } else if (!(n & IWN_POLLOUT)) {
        break;
      }
    }

    while (br_ssl_engine_current_state(cc) & BR_SSL_RECVAPP) {
      int64_t n = a->on_event((void*) a, a->b.user_data, IWN_POLLIN);
      if (n == -1) {
        goto finish;
      } else if (!(n & IWN_POLLIN)) {
        break;
      }
    }

    nflags = _next_poll(cc);
    pthread_mutex_unlock(&a->mtx), locked = false;
  } while (!read_done || !write_done);

finish:
  if (locked) {
    pthread_mutex_unlock(&a->mtx);
  }
  if (br_ssl_engine_current_state(cc) == BR_SSL_CLOSED) {
    int err = br_ssl_engine_last_error(cc);
    if (err != BR_ERR_OK) {
#ifdef _DEBUG
      const char *comment = 0;
      const char *error = find_error_name(err, &comment);
      if (error) {
        if (comment) {
          iwlog_debug("brssl | error code: %d, %s, %s", err, error, comment);
        } else {
          iwlog_debug("brssl | error code: %d, %s", err, error);
        }
      } else {
        iwlog_debug("brssl | error code: %d", err);
      }
#endif
    }
  }

  return nflags;
}

static void x509_start_chain(
  const br_x509_class **ctx,
  const char           *server_name) {
  struct x509_client_context *x509 = (void*) ctx;
  if (!x509->verifyhost) {
    server_name = 0;
  }
  x509->minimal.vtable->start_chain(&x509->minimal.vtable, server_name);
}

static void x509_start_cert(const br_x509_class **ctx, uint32_t length) {
  struct x509_client_context *x509 = (void*) ctx;
  x509->minimal.vtable->start_cert(&x509->minimal.vtable, length);
}

static void x509_append(
  const br_x509_class **ctx,
  const unsigned char  *buf,
  size_t                len) {
  struct x509_client_context *x509 = (void*) ctx;
  x509->minimal.vtable->append(&x509->minimal.vtable, buf, len);
}

static void x509_end_cert(const br_x509_class **ctx) {
  struct x509_client_context *x509 = (void*) ctx;
  x509->minimal.vtable->end_cert(&x509->minimal.vtable);
}

static unsigned x509_end_chain(const br_x509_class **ctx) {
  struct x509_client_context *x509 = (void*) ctx;
  unsigned err = x509->minimal.vtable->end_chain(&x509->minimal.vtable);
  if (err && !x509->verifypeer) {
    /* ignore any X.509 errors */
    err = BR_ERR_OK;
  }
  return err;
}

static const br_x509_pkey* x509_get_pkey(
  const br_x509_class* const *ctx,
  unsigned                   *usages) {
  struct x509_client_context *x509 = (void*) ctx;
  return x509->minimal.vtable->get_pkey(&x509->minimal.vtable, usages);
}

static const br_x509_class x509_vtable = {
  sizeof(struct x509_client_context),
  x509_start_chain,
  x509_start_cert,
  x509_append,
  x509_end_cert,
  x509_end_chain,
  x509_get_pkey
};

struct iwn_brssl_server_config {
  struct iwpool *pool;
  const char   **alpn_protocol_names;
  ssize_t alpn_protocol_names_len;
  br_x509_certificate *certs;
  size_t       certs_num;
  private_key *pk;
};

static iwrc _read_certs(
  const char           *data,
  ssize_t               len,
  bool                  in_buffer,
  br_x509_certificate **out_certs,
  size_t               *out_certs_num) {
  if (in_buffer) {
    *out_certs = read_certificates_data(data, (size_t) len, out_certs_num);
    if (!*out_certs) {
      iwlog_error2("Error reading server certs data specified in buffer");
      return BRS_ERROR_INVALID_CASCERT_DATA;
    }
    return 0;
  }

  char *buf = malloc((size_t) len + 1);
  if (!buf) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  memcpy(buf, data, (size_t) len);
  buf[len] = '\0';
  *out_certs = read_certificates(buf, out_certs_num);
  free(buf);
  if (!*out_certs) {
    iwlog_error("Error reading server certs file: %.*s", (int) len, data);
    return BRS_ERROR_INVALID_CASCERT_DATA;
  }
  return 0;
}

static iwrc _read_key(const char *data, ssize_t len, bool in_buffer, private_key **out_pk) {
  if (in_buffer) {
    *out_pk = read_private_key_data(data, (size_t) len);
    if (!*out_pk) {
      iwlog_error2("Error reading server private key data specified in buffer");
      return BRS_ERROR_INVALID_PRIVKEY_DATA;
    }
    return 0;
  }

  char *buf = malloc((size_t) len + 1);
  if (!buf) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  memcpy(buf, data, (size_t) len);
  buf[len] = '\0';
  *out_pk = read_private_key(buf);
  free(buf);
  if (!*out_pk) {
    iwlog_error("Error reading server private key file: %.*s", (int) len, data);
    return BRS_ERROR_INVALID_PRIVKEY_DATA;
  }
  return 0;
}

/// Configures the server engine of `a` with the provided certificate chain,
/// private key and ALPN protocol names, which are only referenced by the engine.
static void _server_engine_init(
  struct pa                 *a,
  const br_x509_certificate *certs,
  size_t                     certs_num,
  const private_key         *pk,
  const char               **alpn_protocol_names,
  size_t                     alpn_protocol_names_len) {
  if (pk->key_type == BR_KEYTYPE_EC) {
    br_ssl_server_init_full_ec(&a->server.sc, certs, certs_num, BR_KEYTYPE_EC, &pk->key.ec);
  } else {
    br_ssl_server_init_full_rsa(&a->server.sc, certs, certs_num, &pk->key.rsa);
  }
  br_ssl_engine_set_buffer(&a->server.sc.eng, a->iobuf, sizeof(a->iobuf), 1);
  br_ssl_engine_set_versions(&a->server.sc.eng, BR_TLS11, BR_TLS12);
  if (alpn_protocol_names_len > 0) {
    br_ssl_engine_set_protocol_names(&a->server.sc.eng, alpn_protocol_names, alpn_protocol_names_len);
    br_ssl_engine_add_flags(&a->server.sc.eng, BR_OPT_FAIL_ON_ALPN_MISMATCH);
  }
  br_ssl_server_reset(&a->server.sc);
  a->eng = &a->server.sc.eng;
}

static iwrc _server_adapter_create(const struct iwn_tls_server_poller_adapter_spec *spec, struct pa **out) {
  *out = 0;
  if (!spec->poller) {
    iwlog_ecode_error2(IW_ERROR_INVALID_ARGS, "No poller specified");
    return IW_ERROR_INVALID_ARGS;
  }
  if (!spec->on_event) {
    iwlog_ecode_error2(IW_ERROR_INVALID_ARGS, "No on_event specified");
    return IW_ERROR_INVALID_ARGS;
  }

  _init();

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

#if defined(SO_NOSIGPIPE)
  {
    // Apple platforms have no MSG_NOSIGNAL: suppress SIGPIPE on the socket.
    int one = 1;
    setsockopt(spec->fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
  }
#endif
  a->b.fd = spec->fd;
  a->b.poller = spec->poller;
  a->b.read = _read;
  a->b.write = _write;
  a->b.arm = _arm;
  a->b.get_protocol_name = _get_protocol_name;
  a->b.has_pending_write_bytes = _has_pending_write_bytes;
  a->b.user_data = spec->user_data;
  a->on_event = spec->on_event;
  a->on_dispose = spec->on_dispose;

  pthread_mutexattr_t attr;
  pthread_mutexattr_init(&attr);
  pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
  pthread_mutex_init(&a->mtx, &attr);
  pthread_mutexattr_destroy(&attr);

  *out = a;
  return 0;
}

static iwrc _server_adapter_start(
  struct pa                                       *a,
  const struct iwn_tls_server_poller_adapter_spec *spec,
  const br_x509_certificate                       *certs,
  size_t                                           certs_num,
  const private_key                               *pk,
  const char                                     **alpn_protocol_names,
  size_t                                           alpn_protocol_names_len) {
  _server_engine_init(a, certs, certs_num, pk, alpn_protocol_names, alpn_protocol_names_len);
  return iwn_poller_add(&(struct iwn_poller_task) {
    .fd = spec->fd,
    .poller = spec->poller,
    .user_data = a,
    .on_ready = _on_ready,
    .on_dispose = _on_dispose,
    .timeout = spec->timeout_sec,
    .events = spec->events,
    .events_mod = spec->events_mod,
  });
}

iwrc iwn_brssl_server_config_new(
  const struct iwn_tls_server_config_spec *spec,
  struct iwn_brssl_server_config         **out_config) {
  iwrc rc = 0;
  if (!spec || !out_config || !spec->certs || !spec->private_key) {
    return IW_ERROR_INVALID_ARGS;
  }
  *out_config = 0;

  ssize_t certs_len = spec->certs_len < 0 ? (ssize_t) strlen(spec->certs) : spec->certs_len;
  ssize_t private_key_len = spec->private_key_len < 0 ? (ssize_t) strlen(spec->private_key) : spec->private_key_len;
  if (certs_len < 1 || private_key_len < 1) {
    iwlog_ecode_error2(IW_ERROR_INVALID_ARGS, "Certs or private_key data is empty");
    return IW_ERROR_INVALID_ARGS;
  }

  _init();

  struct iwpool *pool = iwpool_create_empty();
  if (!pool) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  struct iwn_brssl_server_config *config = iwpool_calloc(sizeof(*config), pool);
  if (!config) {
    iwpool_destroy(pool);
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  config->pool = pool;

  if (spec->alpn_protocol_names) {
    const char **pnames = iwpool_split_string(pool, spec->alpn_protocol_names, ",", true);
    RCB(finish, pnames);
    config->alpn_protocol_names = pnames;
    for (const char **pn = pnames; *pn; ++pn) {
      config->alpn_protocol_names_len++;
    }
  }

  RCC(rc, finish, _read_certs(spec->certs, certs_len, spec->certs_in_buffer,
                              &config->certs, &config->certs_num));
  RCC(rc, finish, _read_key(spec->private_key, private_key_len, spec->private_key_in_buffer,
                            &config->pk));

finish:
  if (rc) {
    iwn_brssl_server_config_free(config);
  } else {
    *out_config = config;
  }
  return rc;
}

void iwn_brssl_server_config_free(struct iwn_brssl_server_config *config) {
  if (!config) {
    return;
  }
  if (config->pk) {
    free_private_key(config->pk);
  }
  if (config->certs) {
    free_certificates(config->certs, config->certs_num);
  }
  iwpool_destroy(config->pool);
}

iwrc iwn_brssl_server_poller_adapter(const struct iwn_brssl_server_poller_adapter_spec *spec) {
  iwrc rc = 0;
  struct pa *a = 0;
  struct iwn_brssl_server_config *config = 0;

  if (!spec) {
    return IW_ERROR_INVALID_ARGS;
  }
  if (!spec->poller) {
    rc = IW_ERROR_INVALID_ARGS;
    iwlog_ecode_error2(rc, "No poller specified");
    return rc;
  }
  if (!spec->on_event) {
    rc = IW_ERROR_INVALID_ARGS;
    iwlog_ecode_error2(rc, "No on_event specified");
    return rc;
  }
  if (!spec->certs) {
    rc = IW_ERROR_INVALID_ARGS;
    iwlog_ecode_error2(rc, "No certs specified");
    return rc;
  }
  ssize_t certs_len = spec->certs_len;
  if (certs_len < 0) {
    certs_len = strlen(spec->certs);
  }
  if (certs_len < 1) {
    rc = IW_ERROR_INVALID_ARGS;
    iwlog_ecode_error2(rc, "Certs data is empty");
    return rc;
  }
  if (!spec->private_key) {
    rc = IW_ERROR_INVALID_ARGS;
    iwlog_ecode_error2(rc, "No private_key specified");
    return rc;
  }
  ssize_t private_key_len = spec->private_key_len;
  if (private_key_len < 0) {
    private_key_len = strlen(spec->private_key);
  }
  if (private_key_len < 1) {
    rc = IW_ERROR_INVALID_ARGS;
    iwlog_ecode_error2(rc, "Private_key data is empty");
    return rc;
  }

  // The server adapter internals operate on the generic TLS server adapter spec.
  const struct iwn_tls_server_poller_adapter_spec gspec = {
    .poller = spec->poller,
    .on_event = spec->on_event,
    .on_dispose = spec->on_dispose,
    .alpn_protocol_names = spec->alpn_protocol_names,
    .certs = spec->certs,
    .private_key = spec->private_key,
    .certs_len = spec->certs_len,
    .private_key_len = spec->private_key_len,
    .user_data = spec->user_data,
    .timeout_sec = spec->timeout_sec,
    .events = spec->events,
    .events_mod = spec->events_mod,
    .fd = spec->fd,
    .certs_in_buffer = spec->certs_in_buffer,
    .private_key_in_buffer = spec->private_key_in_buffer,
  };

  RCC(rc, finish, iwn_brssl_server_config_new(&(struct iwn_tls_server_config_spec) {
    .tls_impl = IWN_TLS_IMPL_BEARSSL,
    .alpn_protocol_names = spec->alpn_protocol_names,
    .certs = spec->certs,
    .certs_in_buffer = spec->certs_in_buffer,
    .certs_len = spec->certs_len,
    .private_key = spec->private_key,
    .private_key_in_buffer = spec->private_key_in_buffer,
    .private_key_len = spec->private_key_len,
  }, &config));

  RCC(rc, finish, _server_adapter_create(&gspec, &a));
  a->owned_server_config = config;
  config = 0;
  rc = _server_adapter_start(a, &gspec, a->owned_server_config->certs, a->owned_server_config->certs_num,
                             a->owned_server_config->pk, a->owned_server_config->alpn_protocol_names,
                             (size_t) a->owned_server_config->alpn_protocol_names_len);

finish:
  if (rc) {
    if (a) {
      _destroy(a);
    } else {
      iwn_brssl_server_config_free(config);
    }
  }
  return rc;
}

iwrc iwn_brssl_server_poller_adapter_borrow(
  const struct iwn_tls_server_poller_adapter_spec *spec,
  const struct iwn_brssl_server_config            *config) {
  iwrc rc = 0;
  struct pa *a = 0;

  if (!spec || !config) {
    return IW_ERROR_INVALID_ARGS;
  }
  RCC(rc, finish, _server_adapter_create(spec, &a));
  rc = _server_adapter_start(a, spec, config->certs, config->certs_num,
                             config->pk, config->alpn_protocol_names,
                             (size_t) config->alpn_protocol_names_len);

finish:
  if (rc && a) {
    _destroy(a);
  }
  return rc;
}

struct iwn_brssl_client_config {
  struct iwpool *pool;
  const char   **alpn_protocol_names;
  ssize_t     alpn_protocol_names_len;
  anchor_list anchors;
};

iwrc iwn_brssl_client_config_new(
  const struct iwn_tls_client_config_spec *spec,
  struct iwn_brssl_client_config         **out_config) {
  iwrc rc = 0;
  if (!spec || !out_config) {
    return IW_ERROR_INVALID_ARGS;
  }
  *out_config = 0;

  const char *cacerts_data = spec->cacerts_data;
  size_t cacerts_data_len = spec->cacerts_data_len;
  if (!cacerts_data || !cacerts_data_len) {
    cacerts_data = iwn_cacerts;
    cacerts_data_len = iwn_cacerts_len;
  }

  _init();

  struct iwpool *pool = iwpool_create_empty();
  if (!pool) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  struct iwn_brssl_client_config *config = iwpool_calloc(sizeof(*config), pool);
  if (!config) {
    iwpool_destroy(pool);
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  config->pool = pool;

  if (spec->alpn_protocol_names) {
    const char **pnames = iwpool_split_string(pool, spec->alpn_protocol_names, ",", true);
    RCB(finish, pnames);
    config->alpn_protocol_names = pnames;
    for (const char **pn = pnames; *pn; ++pn) {
      config->alpn_protocol_names_len++;
    }
  }

  if (!read_trust_anchors_data(&config->anchors, cacerts_data, cacerts_data_len)) {
    iwlog_ecode_error2(BRS_ERROR_INVALID_CASCERT_DATA, "Unable to load CA certificates");
    rc = BRS_ERROR_INVALID_CASCERT_DATA;
    goto finish;
  }

finish:
  if (rc) {
    iwn_brssl_client_config_free(config);
  } else {
    *out_config = config;
  }
  return rc;
}

void iwn_brssl_client_config_free(struct iwn_brssl_client_config *config) {
  if (!config) {
    return;
  }
  VEC_CLEAREXT(config->anchors, &free_ta_contents);
  iwpool_destroy(config->pool);
}

static iwrc _client_adapter_create(const struct iwn_tls_client_poller_adapter_spec *spec, struct pa **out) {
  *out = 0;
  if (!spec->poller) {
    iwlog_ecode_error2(IW_ERROR_INVALID_ARGS, "No poller specified");
    return IW_ERROR_INVALID_ARGS;
  }
  if (!spec->on_event) {
    iwlog_ecode_error2(IW_ERROR_INVALID_ARGS, "No on_event specified");
    return IW_ERROR_INVALID_ARGS;
  }

  _init();

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
  a->is_client = true;
  a->b.fd = spec->fd;
  a->b.poller = spec->poller;
  a->b.read = _read;
  a->b.write = _write;
  a->b.arm = _arm;
  a->b.get_protocol_name = _get_protocol_name;
  a->b.has_pending_write_bytes = _has_pending_write_bytes;
  a->b.user_data = spec->user_data;
  a->on_event = spec->on_event;
  a->on_dispose = spec->on_dispose;

  pthread_mutexattr_t attr;
  pthread_mutexattr_init(&attr);
  pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
  pthread_mutex_init(&a->mtx, &attr);
  pthread_mutexattr_destroy(&attr);

  *out = a;
  return 0;
}

/// Configures the client engine of `a`. The trust anchors and ALPN protocol names
/// are only referenced by the engine.
static iwrc _client_adapter_start(
  struct pa                                       *a,
  const struct iwn_tls_client_poller_adapter_spec *spec,
  const br_x509_trust_anchor                      *anchors,
  size_t                                           anchors_num,
  const char                                     **alpn_protocol_names,
  size_t                                           alpn_protocol_names_len) {
  br_ssl_client_init_full(&a->client.cc, &a->client.x509.minimal, anchors, anchors_num);
  br_ssl_engine_set_buffer(&a->client.cc.eng, a->iobuf, sizeof(a->iobuf), 1);
  br_ssl_engine_set_versions(&a->client.cc.eng, BR_TLS11, BR_TLS12);
  if (alpn_protocol_names_len > 0) {
    br_ssl_engine_set_protocol_names(&a->client.cc.eng, alpn_protocol_names, alpn_protocol_names_len);
    br_ssl_engine_add_flags(&a->client.cc.eng, BR_OPT_FAIL_ON_ALPN_MISMATCH);
  }
  a->client.x509.vtable = &x509_vtable;
  a->client.x509.verifyhost = spec->verify_host;
  a->client.x509.verifypeer = spec->verify_peer;
  br_ssl_engine_set_x509(&a->client.cc.eng, &a->client.x509.vtable);
  br_ssl_client_reset(&a->client.cc, spec->host, 0);

  a->eng = &a->client.cc.eng;

  return iwn_poller_add(&(struct iwn_poller_task) {
    .fd = spec->fd,
    .poller = spec->poller,
    .user_data = a,
    .on_ready = _on_ready,
    .on_dispose = _on_dispose,
    .timeout = spec->timeout_sec,
    .events = spec->events,
    .events_mod = spec->events_mod,
  });
}

iwrc iwn_brssl_client_poller_adapter_borrow(
  const struct iwn_tls_client_poller_adapter_spec *spec,
  const struct iwn_brssl_client_config            *config) {
  iwrc rc = 0;
  struct pa *a = 0;

  if (!spec || !config) {
    return IW_ERROR_INVALID_ARGS;
  }
  RCC(rc, finish, _client_adapter_create(spec, &a));
  rc = _client_adapter_start(a, spec, config->anchors.buf, config->anchors.ptr,
                             config->alpn_protocol_names,
                             (size_t) config->alpn_protocol_names_len);

finish:
  if (rc && a) {
    _destroy(a);
  }
  return rc;
}

iwrc iwn_brssl_client_poller_adapter(const struct iwn_brssl_client_poller_adapter_spec *spec) {
  iwrc rc = 0;
  struct pa *a = 0;
  struct iwn_brssl_client_config *config = 0;

  if (!spec) {
    return IW_ERROR_INVALID_ARGS;
  }
  if (!spec->poller) {
    rc = IW_ERROR_INVALID_ARGS;
    iwlog_ecode_error2(rc, "No poller specified");
    return rc;
  }
  if (!spec->on_event) {
    rc = IW_ERROR_INVALID_ARGS;
    iwlog_ecode_error2(rc, "No on_event specified");
    return rc;
  }

  // The client adapter internals operate on the generic TLS client adapter spec.
  const struct iwn_tls_client_poller_adapter_spec gspec = {
    .tls_impl = IWN_TLS_IMPL_BEARSSL,
    .poller = spec->poller,
    .host = spec->host,
    .on_event = spec->on_event,
    .on_dispose = spec->on_dispose,
    .user_data = spec->user_data,
    .timeout_sec = spec->timeout_sec,
    .events = spec->events,
    .events_mod = spec->events_mod,
    .fd = spec->fd,
    .verify_peer = spec->verify_peer,
    .verify_host = spec->verify_host,
  };

  RCC(rc, finish, iwn_brssl_client_config_new(&(struct iwn_tls_client_config_spec) {
    .tls_impl = IWN_TLS_IMPL_BEARSSL,
    .alpn_protocol_names = spec->alpn_protocol_names,
    .cacerts_data = spec->cacerts_data,
    .cacerts_data_len = spec->cacerts_data_len,
    .verify_peer = spec->verify_peer,
    .verify_host = spec->verify_host,
  }, &config));

  RCC(rc, finish, _client_adapter_create(&gspec, &a));
  a->owned_client_config = config;
  config = 0;
  rc = _client_adapter_start(a, &gspec, a->owned_client_config->anchors.buf,
                             a->owned_client_config->anchors.ptr,
                             a->owned_client_config->alpn_protocol_names,
                             (size_t) a->owned_client_config->alpn_protocol_names_len);

finish:
  if (rc) {
    if (a) {
      _destroy(a);
    } else {
      iwn_brssl_client_config_free(config);
    }
  }
  return rc;
}

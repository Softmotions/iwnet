#include "iwnet.h"
#include "iwn_brssl_poller_adapter.h"

#include "bearssl/brssl.h"
#include <iowow/iwlog.h>

#include <stdlib.h>
#include <errno.h>
#include <pthread.h>
#include <unistd.h>

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
  br_ssl_engine_context *eng;
  pthread_mutex_t mtx;
  pthread_key_t   ready_fd_tl;

  union {
    struct  {
      br_ssl_client_context      cc;
      struct x509_client_context x509;
      anchor_list anchors;
    } client;

    struct {
      br_ssl_server_context sc;
      private_key *pk;
      br_x509_certificate *certs;
      size_t certs_num;
    } server;
  };

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
  if (a->is_client) {
    VEC_CLEAREXT(a->client.anchors, &free_ta_contents);
  } else {
    free_private_key(a->server.pk);
    if (a->server.certs_num) {
      free_certificates(a->server.certs, a->server.certs_num);
    }
  }
  pthread_key_delete(a->ready_fd_tl);
  pthread_mutex_destroy(&a->mtx);
  free(a);
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
    ssize_t wlen = write(a->b.fd, buf, len);
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

static void _has_pending_write_bytes_probe(struct iwn_poller *p, void *slot_user_data, void *fn_user_data) {
  struct pa *a = slot_user_data;
  bool *ret = fn_user_data;
  br_ssl_engine_context *cc = a->eng;
  pthread_mutex_lock(&a->mtx);
  *ret = (br_ssl_engine_current_state(cc) & BR_SSL_SENDREC) != 0;
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

iwrc _arm(struct iwn_poller_adapter *a, uint32_t events) {
  if (_arm_needed(a)) {
    return iwn_poller_arm_events(a->poller, a->fd, events);
  }
  return 0;
}

static int64_t _on_ready(const struct iwn_poller_task *t, uint32_t flags) {
  struct pa *a = t->user_data;
  br_ssl_engine_context *cc = a->eng;
  bool write_done, read_done;
  bool locked = false;
  int64_t nflags;

  pthread_setspecific(a->ready_fd_tl, (void*) 1);

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

  pthread_setspecific(a->ready_fd_tl, 0);
  return nflags;
}

static void x509_start_chain(
  const br_x509_class **ctx,
  const char           *server_name
  ) {
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
  size_t                len
  ) {
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
  unsigned                   *usages
  ) {
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

iwrc iwn_brssl_server_poller_adapter(const struct iwn_brssl_server_poller_adapter_spec *spec) {
  struct iwn_poller *p = spec->poller;
  iwrc rc = 0;

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

  _init();

  struct pa *a = calloc(1, sizeof(*a));
  if (!a) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  a->b.fd = spec->fd;
  a->b.poller = p;
  a->b.read = _read;
  a->b.write = _write;
  a->b.arm = _arm;
  a->b.has_pending_write_bytes = _has_pending_write_bytes;
  a->b.user_data = spec->user_data;
  a->on_event = spec->on_event;
  a->on_dispose = spec->on_dispose;

  pthread_mutexattr_t attr;
  pthread_mutexattr_init(&attr);
  pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
  pthread_mutex_init(&a->mtx, &attr);
  pthread_mutexattr_destroy(&attr);

  pthread_key_create(&a->ready_fd_tl, 0);

  if (spec->certs_in_buffer) {
    a->server.certs = read_certificates_data(spec->certs, certs_len, &a->server.certs_num);
    if (!a->server.certs) {
      iwlog_error2("Error reading server certs data specified in buffer");
      rc = BRS_ERROR_INVALID_CASCERT_DATA;
      goto finish;
    }
  } else {
    char *buf = malloc(certs_len + 1);
    RCA(buf, finish);
    memcpy(buf, spec->certs, certs_len);
    buf[certs_len] = '\0';
    a->server.certs = read_certificates(buf, &a->server.certs_num);
    free(buf);
    if (!a->server.certs) {
      iwlog_error("Error reading server certs file: %.*s", (int) certs_len, spec->certs);
      rc = BRS_ERROR_INVALID_CASCERT_DATA;
      goto finish;
    }
  }

  if (spec->private_key_in_buffer) {
    a->server.pk = read_private_key_data(spec->private_key, private_key_len);
    if (!a->server.pk) {
      iwlog_error2("Error reading server private key data specified in buffer");
      rc = BRS_ERROR_INVALID_PRIVKEY_DATA;
      goto finish;
    }
  } else {
    char *buf = malloc(private_key_len + 1);
    RCA(buf, finish);
    memcpy(buf, spec->private_key, private_key_len);
    buf[private_key_len] = '\0';
    a->server.pk = read_private_key(buf);
    free(buf);
    if (!a->server.pk) {
      iwlog_error("Error reading server private key file: %.*s", (int) private_key_len, spec->private_key);
      rc = BRS_ERROR_INVALID_PRIVKEY_DATA;
      goto finish;
    }
  }

  if (a->server.pk->key_type == BR_KEYTYPE_EC) {
    br_ssl_server_init_full_ec(&a->server.sc,
                               a->server.certs,
                               a->server.certs_num,
                               BR_KEYTYPE_EC,
                               &a->server.pk->key.ec);
  } else {
    br_ssl_server_init_full_rsa(&a->server.sc,
                                a->server.certs,
                                a->server.certs_num,
                                &a->server.pk->key.rsa);
  }

  br_ssl_engine_set_buffer(&a->server.sc.eng, a->iobuf, sizeof(a->iobuf), 1);
  br_ssl_engine_set_versions(&a->server.sc.eng, BR_TLS11, BR_TLS12);
  br_ssl_server_reset(&a->server.sc);

  a->eng = &a->server.sc.eng;

  rc = iwn_poller_add(&(struct iwn_poller_task) {
    .fd = spec->fd,
    .poller = p,
    .user_data = a,
    .on_ready = _on_ready,
    .on_dispose = _on_dispose,
    .timeout = spec->timeout_sec,
    .events = spec->events
  });

finish:
  if (rc) {
    _destroy(a);
  }
  return rc;
}

iwrc iwn_brssl_client_poller_adapter(const struct iwn_brssl_client_poller_adapter_spec *spec) {
  struct iwn_poller *p = spec->poller;
  iwrc rc = 0;
  int rci = 0;

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

  _init();

  struct pa *a = calloc(1, sizeof(*a));
  if (!a) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  a->is_client = true;
  a->b.fd = spec->fd;
  a->b.poller = p;
  a->b.read = _read;
  a->b.write = _write;
  a->b.arm = _arm;
  a->b.user_data = spec->user_data;
  a->b.has_pending_write_bytes = _has_pending_write_bytes;
  a->on_event = spec->on_event;
  a->on_dispose = spec->on_dispose;

  pthread_mutexattr_t attr;
  pthread_mutexattr_init(&attr);
  pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
  pthread_mutex_init(&a->mtx, &attr);
  pthread_mutexattr_destroy(&attr);

  pthread_key_create(&a->ready_fd_tl, 0);

  const char *cacerts_data = spec->cacerts_data;
  size_t cacerts_data_len = spec->cacerts_data_len;
  if (!cacerts_data || !cacerts_data_len) {
    cacerts_data = iwn_cacerts;
    cacerts_data_len = iwn_cacerts_len;
  }

  // Load trust anchors
  rci = read_trust_anchors_data(&a->client.anchors, cacerts_data, cacerts_data_len);
  if (!rci) {
    rc = BRS_ERROR_INVALID_CASCERT_DATA;
    goto finish;
  }

  br_ssl_client_init_full(&a->client.cc, &a->client.x509.minimal, a->client.anchors.buf, a->client.anchors.ptr);
  br_ssl_engine_set_buffer(&a->client.cc.eng, a->iobuf, sizeof(a->iobuf), 1);
  br_ssl_engine_set_versions(&a->client.cc.eng, BR_TLS11, BR_TLS12);

  a->client.x509.vtable = &x509_vtable;
  a->client.x509.verifyhost = spec->verify_host;
  a->client.x509.verifypeer = spec->verify_peer;
  br_ssl_engine_set_x509(&a->client.cc.eng, &a->client.x509.vtable);
  br_ssl_client_reset(&a->client.cc, spec->host, 0);

  a->eng = &a->client.cc.eng;

  rc = iwn_poller_add(&(struct iwn_poller_task) {
    .fd = spec->fd,
    .poller = p,
    .user_data = a,
    .on_ready = _on_ready,
    .on_dispose = _on_dispose,
    .timeout = spec->timeout_sec,
    .events = spec->events
  });

finish:
  if (rc) {
    _destroy(a);
  }
  return rc;
}

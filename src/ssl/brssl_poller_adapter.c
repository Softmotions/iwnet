#include "iwnet.h"
#include "brssl_poller_adapter.h"

#include <iowow/iwlog.h>

#include <brssl.h>
#include <stdlib.h>
#include <errno.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/epoll.h>

struct x509_context {
  const br_x509_class    *vtable;
  br_x509_minimal_context minimal;
  bool verifyhost;
  bool verifypeer;
};

struct _pa {
  struct iwn_poller_adapter     b;
  iwn_on_poller_adapter_event   on_event;
  iwn_on_poller_adapter_dispose on_dispose;
  void *user_data;
  pthread_mutex_t       mtx;
  br_ssl_client_context bc;
  struct x509_context   x509;
  anchor_list   anchors;
  unsigned char iobuf[BR_SSL_BUFSIZE_BIDI];
};

static volatile bool _initialized = false;

static const char* _ecodefn(locale_t locale, uint32_t ecode) {
  if (ecode <= _BRS_ERROR_START || ecode >= _BRS_ERROR_END) {
    return 0;
  }
  switch (ecode) {
    case BRS_ERROR_INVALID_CASCERT_DATA:
      return "Invalid CA cetificates (BRS_ERROR_INVALID_CASCERT_DATA)";
  }
  return 0;
}

static void _init(void) {
  if (__sync_bool_compare_and_swap(&_initialized, false, true)) {
    iwlog_register_ecodefn(_ecodefn);
  }
}

static ssize_t _read(struct iwn_poller_adapter *pa, uint8_t *data, size_t len) {
  struct _pa *a = (void*) pa;
  br_ssl_engine_context *cc = &a->bc.eng;
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
  struct _pa *a = (void*) pa;
  br_ssl_engine_context *cc = &a->bc.eng;
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

IW_INLINE void _destroy(struct _pa *a) {
  VEC_CLEAREXT(a->anchors, &free_ta_contents);
  free(a);
}

static void _on_dispose(const struct iwn_poller_task *t) {
  struct _pa *a = t->user_data;
  a->on_dispose((void*) a, a->user_data);
  _destroy(a);
}

static int _write_fd(struct _pa *a, const unsigned char *buf, size_t len) {
  while (1) {
    ssize_t wlen = write(a->b.fd, buf, len);
    if (wlen < 0 && errno == EINTR) {
      continue;
    }
    return (int) wlen;
  }
}

static int _read_fd(struct _pa *a, unsigned char *buf, size_t len) {
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
  uint32_t st = br_ssl_engine_current_state(cc);
  if (st & BR_SSL_CLOSED) {
    return -1;
  }
  if (st & BR_SSL_RECVREC) {
    ret |= EPOLLIN;
  }
  if (st & BR_SSL_SENDREC) {
    ret |= EPOLLOUT;
  }
  if (ret == 0) {
    ret |= EPOLLIN;
  }
  return ret | EPOLLET;
}

static int64_t _on_ready(const struct iwn_poller_task *t, uint32_t flags) {
  struct _pa *a = t->user_data;
  br_ssl_engine_context *cc = &a->bc.eng;
  bool done = !(flags & EPOLLIN);
  bool locked = false;
  int64_t nflags;

  do {
    nflags = -1;
    pthread_mutex_lock(&a->mtx), locked = true;

    if (br_ssl_engine_current_state(cc) == BR_SSL_CLOSED) {
      goto finish;
    }

    while (br_ssl_engine_current_state(cc) & BR_SSL_SENDREC) {
      size_t len;
      unsigned char *buf = br_ssl_engine_sendrec_buf(cc, &len);
      int wlen = _write_fd(a, buf, len);
      if (wlen == 0) {
        goto finish;
      } else if (wlen < 0) {
        if (errno == EWOULDBLOCK || errno == EAGAIN) {
          done = true;
          break;
        } else {
          goto finish;
        }
      }
      br_ssl_engine_sendrec_ack(cc, wlen);
    }

    while (br_ssl_engine_current_state(cc) & BR_SSL_RECVREC) {
      size_t len;
      unsigned char *buf = br_ssl_engine_recvrec_buf(cc, &len);
      int rlen = _read_fd(a, buf, len);
      if (rlen == 0) {
        goto finish;
      } else if (rlen < 0) {
        if (errno == EWOULDBLOCK || errno == EAGAIN) {
          done = true;
          break;
        } else {
          goto finish;
        }
      }
      br_ssl_engine_recvrec_ack(cc, rlen);
    }

    while (br_ssl_engine_current_state(cc) & BR_SSL_SENDAPP) {
      int64_t n = a->on_event((void*) a, a->user_data, EPOLLOUT);
      if (n == -1) {
        goto finish;
      } else if (!(n & EPOLLOUT)) {
        break;
      }
    }

    while (br_ssl_engine_current_state(cc) & BR_SSL_RECVAPP) {
      int64_t n = a->on_event((void*) a, a->user_data, EPOLLIN);
      if (n == -1) {
        goto finish;
      } else if (!(n & EPOLLIN)) {
        break;
      }
    }

    nflags = _next_poll(cc);
    pthread_mutex_unlock(&a->mtx), locked = false;
  } while (!done);

finish:
  if (locked) {
    pthread_mutex_unlock(&a->mtx);
  }
  if (br_ssl_engine_current_state(cc) == BR_SSL_CLOSED) {
    int err = br_ssl_engine_last_error(cc);
    if (err != BR_ERR_OK) {
      iwlog_warn("brssl | error code: %d", err);
    }
  }
  return nflags;
}

static void x509_start_chain(
  const br_x509_class **ctx,
  const char           *server_name) {
  struct x509_context *x509 = (void*) ctx;
  if (!x509->verifyhost) {
    server_name = 0;
  }
  x509->minimal.vtable->start_chain(&x509->minimal.vtable, server_name);
}

static void x509_start_cert(const br_x509_class **ctx, uint32_t length) {
  struct x509_context *x509 = (void*) ctx;
  x509->minimal.vtable->start_cert(&x509->minimal.vtable, length);
}

static void x509_append(
  const br_x509_class **ctx,
  const unsigned char  *buf,
  size_t                len) {
  struct x509_context *x509 = (void*) ctx;
  x509->minimal.vtable->append(&x509->minimal.vtable, buf, len);
}

static void x509_end_cert(const br_x509_class **ctx) {
  struct x509_context *x509 = (void*) ctx;
  x509->minimal.vtable->end_cert(&x509->minimal.vtable);
}

static unsigned x509_end_chain(const br_x509_class **ctx) {
  struct x509_context *x509 = (void*) ctx;
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
  struct x509_context *x509 = (void*) ctx;
  return x509->minimal.vtable->get_pkey(&x509->minimal.vtable, usages);
}

static const br_x509_class x509_vtable = {
  sizeof(struct x509_context),
  x509_start_chain,
  x509_start_cert,
  x509_append,
  x509_end_cert,
  x509_end_chain,
  x509_get_pkey
};




iwrc iwn_brssl_client_poller_adapter(const struct iwn_brssl_client_poller_adapter_spec *spec) {
  struct iwn_poller *p = spec->poller;
  iwrc rc = 0;
  int rci = 0;

  _init();

  struct _pa *a = calloc(1, sizeof(*a));
  if (!a) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  a->b.fd = spec->fd;
  a->b.poller = p;
  a->b.read = _read;
  a->b.write = _write;
  a->on_event = spec->on_event;
  a->on_dispose = spec->on_dispose;
  a->user_data = spec->user_data;

  // Load trust anchors
  rci = read_trust_anchors_data(&a->anchors, iwn_cacerts, iwn_cacerts_len);
  if (!rci) {
    rc = BRS_ERROR_INVALID_CASCERT_DATA;
    goto finish;
  }

  br_ssl_client_init_full(&a->bc, &a->x509.minimal, a->anchors.buf, a->anchors.ptr);
  br_ssl_engine_set_buffer(&a->bc.eng, a->iobuf, sizeof(a->iobuf), 1);
  br_ssl_engine_set_versions(&a->bc.eng, BR_TLS11, BR_TLS12);

  a->x509.vtable = &x509_vtable;
  a->x509.verifyhost = spec->verify_host;
  a->x509.verifypeer = spec->verify_peer;
  br_ssl_engine_set_x509(&a->bc.eng, &a->x509.vtable);
  br_ssl_client_reset(&a->bc, spec->host, 0);

  rc = iwn_poller_add(&(struct iwn_poller_task) {
    .fd = spec->fd,
    .poller = p,
    .user_data = a,
    .on_ready = _on_ready,
    .on_dispose = _on_dispose,
    .timeout_sec = spec->timeout_sec,
    .events = spec->events
  });

finish:
  if (rc) {
    _destroy(a);
  }
  return rc;
}

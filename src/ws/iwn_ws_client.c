#include "iwn_ws_client.h"

#include "iwn_poller.h"
#include "poller/iwn_direct_poller_adapter.h"
#include "ssl/iwn_brssl_poller_adapter.h"

#include "iwn_base64.h"
#include "iwn_url.h"
#include "iwn_utils.h"
#include "iwn_scheduler.h"

#include "bearssl/bearssl_hash.h"
#include "wslay/wslay.h"

#include <iowow/iwlog.h>
#include <iowow/iwxstr.h>
#include <iowow/iwutils.h>
#include <iowow/iwchars.h>

#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <assert.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <netinet/in.h>

#define _STATE_HANDSHAKE_SEND 0x01U
#define _STATE_HANDSHAKE_RECV 0x02U

#define _FLAG_SECURE     0x01U
#define _FLAG_NO_NETWORK 0x02U

struct iwn_ws_client {
  struct iwn_ws_client_ctx   ctx;
  struct iwn_ws_client_spec  spec;
  struct iwn_poller_adapter *pa;
  char *host;
  char *path;
  char *query;
  char *urlbuf;
  char *scheme;
  wslay_event_context_ptr wsl;
  struct iwxstr  *output;
  struct iwxstr  *input;
  pthread_mutex_t mtx;
  int     port;
  int     fd;
  uint8_t state;
  uint8_t flags;
  atomic_uchar  reconnect_attempt;
  volatile bool close_cas;
  volatile bool dispose_cas;
  char client_key[32];
  bool quiet;
};

static bool _initialized;
static const char* _ecodefn(locale_t locale, uint32_t ecode);

IW_INLINE iwrc _wslayrc(enum wslay_error err) {
  if (!err) {
    return 0;
  }
  switch (err) {
    case WSLAY_ERR_NO_MORE_MSG:
      return WS_ERROR_CHANNEL_CLOSED;
    case WSLAY_ERR_INVALID_ARGUMENT:
      return IW_ERROR_INVALID_ARGS;
    case WSLAY_ERR_NOMEM:
      return iwrc_set_errno(IW_ERROR_ALLOC, errno);
    default:
      return WS_ERROR;
  }
}

static void _ws_destroy(struct iwn_ws_client *ws) {
  if (ws) {
    free(ws->path);
    free(ws->urlbuf);
    wslay_event_context_free(ws->wsl);
    iwxstr_destroy(ws->output);
    iwxstr_destroy(ws->input);
    pthread_mutex_destroy(&ws->mtx);
    free(ws);
  }
}

static iwrc _fd_make_non_blocking(int fd) {
  int rci, flags;
  while ((flags = fcntl(fd, F_GETFL, 0)) == -1 && errno == EINTR);
  if (flags == -1) {
    return iwrc_set_errno(IW_ERROR_ERRNO, errno);
  }
  while ((rci = fcntl(fd, F_SETFL, flags | O_NONBLOCK)) == -1 && errno == EINTR);
  if (rci == -1) {
    return iwrc_set_errno(IW_ERROR_ERRNO, errno);
  }
  return 0;
}

static iwrc _connect(struct iwn_ws_client *ws, bool async, int *out_fd) {
  assert(out_fd);

  *out_fd = 0;

  char nbuf[IWNUMBUF_SIZE];
  snprintf(nbuf, sizeof(nbuf), "%d", ws->port);
  char *port = nbuf;

  iwrc rc = 0;
  int fd = -1, rci;

  struct addrinfo *si = 0, *p = 0, hints = {
    .ai_family = PF_UNSPEC,
    .ai_socktype = SOCK_STREAM
  };

  if (ws->scheme == 0 || strcmp(ws->scheme, "socket") != 0) {
    rci = getaddrinfo(ws->host, port, &hints, &si);
    if (rci) {
      if (!ws->quiet) {
        iwlog_ecode_error(WS_ERROR_PEER_CONNECT, "ws | %s", gai_strerror(rci));
      }
      return WS_ERROR_PEER_CONNECT;
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
        if (!ws->quiet) {
          iwlog_ecode_error(WS_ERROR_PEER_CONNECT, "ws | Unsupported address family: 0x%x", (int) sa->sa_family);
        }
        rc = WS_ERROR_PEER_CONNECT;
        goto finish;
      }

      if (!inet_ntop(p->ai_family, addr, saddr, sizeof(saddr))) {
        rc = iwrc_set_errno(IW_ERROR_ERRNO, errno);
        goto finish;
      }

      fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
      if (fd < 0) {
        if (!ws->quiet) {
          iwlog_warn("ws | Error opening socket %s:%s %s %s", ws->host, port, saddr, strerror(errno));
        }
        continue;
      }

      if (async) {
        RCC(rc, finish, _fd_make_non_blocking(fd));
      }

      do {
        rci = connect(fd, p->ai_addr, p->ai_addrlen);
      } while (errno == EINTR);

      if (rci == -1) {
        if (!(async && (errno == EAGAIN || errno == EINPROGRESS))) {
          if (!ws->quiet) {
            iwlog_warn("ws | Error connecting %s:%s %s %s", ws->host, port, saddr, strerror(errno));
          }
          close(fd), fd = -1;
          continue;
        }
      }
      break;
    }
  } else {
    RCN(finish, fd = socket(AF_UNIX, SOCK_STREAM, 0));

    struct sockaddr_un saddr = {
      .sun_family = AF_UNIX
    };

    if (strlen(ws->host) >= sizeof(saddr.sun_path)) {
      rc = IW_ERROR_INVALID_ARGS;
      if (!ws->quiet) {
        iwlog_ecode_error(rc, "Unix socket path exceeds its maximum length: %zd", sizeof(saddr.sun_path) - 1);
      }
      goto finish;
    }
    strncpy(saddr.sun_path, ws->host, sizeof(saddr.sun_path) - 1);

    do {
      rci = connect(fd, (void*) &saddr, sizeof(saddr));
    } while (errno == EINTR);

    if (rci == -1) {
      if (!(async && (errno == EAGAIN || errno == EINPROGRESS))) {
        if (!ws->quiet) {
          iwlog_warn("ws | Error Unix socket connecting  %s %s", ws->host, strerror(errno));
        }
        close(fd), fd = -1;
        goto finish;
      }
    }
  }

  if (!INVALIDHANDLE(fd)) {
    *out_fd = fd;
  } else {
    rc = WS_ERROR_PEER_CONNECT;
  }

finish:
  if (si) {
    freeaddrinfo(si);
  }
  if (rc) {
    if (fd > -1) {
      close(fd);
    }
  } else if (!async) { // Make socket non-blocking after connection established
    rc = _fd_make_non_blocking(fd);
  }
  return rc;
}

static iwrc _make_tcp_nodelay(int fd) {
  int val = 1;
  if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &val, (socklen_t) sizeof(val)) == -1) {
    return iwrc_set_errno(IW_ERROR_ERRNO, errno);
  } else {
    return 0;
  }
}

static ssize_t _wslay_event_recv_callback(
  wslay_event_context_ptr ctx,
  uint8_t                *buf,
  size_t                  len,
  int                     flags,
  void                   *user_data) {
  ssize_t rci = -1;
  struct iwn_ws_client *ws = user_data;
  struct iwn_poller_adapter *pa = ws->pa;
  assert(pa);

again:
  rci = pa->read(pa, buf, len);
  if (rci == -1) {
    if (errno == EINTR) {
      goto again;
    }
    if (errno == EAGAIN) {
      wslay_event_set_error(ws->wsl, WSLAY_ERR_WOULDBLOCK);
    } else {
      wslay_event_set_error(ws->wsl, WSLAY_ERR_CALLBACK_FAILURE);
    }
  } else if (rci == 0) {
    wslay_event_shutdown_read(ws->wsl);
    rci = -1;
  }
  return rci;
}

static ssize_t _wslay_event_send_callback(
  wslay_event_context_ptr ctx,
  const uint8_t          *buf,
  size_t                  len,
  int                     flags,
  void                   *user_data) {
  ssize_t rci = -1;
  struct iwn_ws_client *ws = user_data;
  struct iwn_poller_adapter *pa = ws->pa;
  assert(pa);

again:
  rci = pa->write(pa, buf, len);
  if (rci == -1) {
    if (errno == EINTR) {
      goto again;
    }
    if (errno == EAGAIN) {
      wslay_event_set_error(ws->wsl, WSLAY_ERR_WOULDBLOCK);
    } else {
      wslay_event_set_error(ws->wsl, WSLAY_ERR_CALLBACK_FAILURE);
    }
  } else if (rci == 0) {
    wslay_event_shutdown_write(ws->wsl);
    rci = -1;
  }
  return rci;
}

static void _wslay_event_on_msg_recv_callback(
  wslay_event_context_ptr                   ctx,
  const struct wslay_event_on_msg_recv_arg *arg,
  void                                     *user_data) {
  struct iwn_ws_client *ws = user_data;
  if (  (  arg->msg_length > 0
        && (arg->opcode == WSLAY_TEXT_FRAME || arg->opcode == WSLAY_BINARY_FRAME))
     || (  (ws->spec.flags & WS_HANDLE_PING_PONG)
        && (arg->opcode == WSLAY_PING || arg->opcode == WSLAY_PONG))) {
    ws->spec.on_message(&ws->ctx, (void*) arg->msg, arg->msg_length, arg->opcode);
  }
}

static int _wslay_genmask_callback(
  wslay_event_context_ptr ctx, uint8_t *buf, size_t len,
  void *user_data) {
  size_t tow = len;
  while (tow > 0) {
    uint32_t rn = iwu_rand_u32();
    size_t wl = tow > sizeof(rn) ? sizeof(rn) : tow;
    memcpy(buf, &rn, wl);
    tow -= wl;
    buf += wl;
  }
  return 0;
}

static iwrc _handshake_write_client_key_b64(char out[32]) {
  size_t len;
  iwrc rc = 0;
  unsigned char buf[16];
  FILE *f = fopen("/dev/urandom", "r");
  if (!f) {
    return iwrc_set_errno(IW_ERROR_IO_ERRNO, errno);
  }
  if (fread(buf, sizeof(buf), 1, f) != 1) {
    fclose(f);
    rc = IW_ERROR_IO_ERRNO;
    goto finish;
  }
  fclose(f);

  if (!iwn_base64_encode(out, 32, &len, buf, sizeof(buf), base64_VARIANT_ORIGINAL)) {
    rc = IW_ERROR_FAIL;
  }

finish:
  if (rc) {
    iwlog_ecode_error3(rc);
  }
  return rc;
}

static iwrc _handshake_output_fill(struct iwn_ws_client *ws) {
  iwxstr_clear(ws->output);
  iwrc rc = RCR(_handshake_write_client_key_b64(ws->client_key));

  static char *er_default = "";
  char *er = er_default;
  if (ws->spec.on_handshake) {
    er = ws->spec.on_handshake(&ws->ctx);
    if (!er) {
      er = er_default;
    }
  }

  const char *host = ws->host;
  if (strchr(host, '/')) {
    // Host is a path-like structure (Eg. Unix socket file)
    // Replace it by fake localhost
    host = "localhost";
  }

  RCR(iwxstr_printf(
        ws->output,
        "GET %s%s%s HTTP/1.1\r\n"
        "Host: %s:%d\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "%s"
        "Sec-Websocket-Key: %s\r\n"
        "Sec-Websocket-Version: 13\r\n"
        "\r\n",
        ws->path, (ws->query ? "?" : ""), (ws->query ? ws->query : ""),
        host, ws->port,
        er,
        ws->client_key));

  if (er != er_default) {
    free(er);
  }
  return rc;
}

static bool _handshake_validate_accept_key(struct iwn_ws_client *ws, const char *accept_key, size_t accept_key_len) {
  size_t len = strlen(ws->client_key);
  unsigned char buf[len + IW_LLEN(WS_MAGIC13)];
  unsigned char sbuf[br_sha1_SIZE];
  char vbuf[br_sha1_SIZE * 2];
  memcpy(buf, ws->client_key, len);
  memcpy(buf + len, WS_MAGIC13, IW_LLEN(WS_MAGIC13));
  br_sha1_context ctx;
  br_sha1_init(&ctx);
  br_sha1_update(&ctx, buf, sizeof(buf));
  br_sha1_out(&ctx, sbuf);
  if (!iwn_base64_encode(vbuf, sizeof(vbuf), &len, sbuf, sizeof(sbuf), base64_VARIANT_ORIGINAL)) {
    return false;
  }
  if (accept_key_len != len - 1) {
    return false;
  }
  return strncmp(vbuf, accept_key, accept_key_len) == 0;
}

static int64_t _on_handshake_event(struct iwn_poller_adapter *pa, void *user_data, uint32_t events) {
  iwrc rc = 0;
  int64_t ret = 0;
  struct iwn_ws_client *ws = user_data;

  if (!(ws->state & _STATE_HANDSHAKE_SEND)) {
    ret = IWN_POLLOUT;
    if (iwxstr_size(ws->output) == 0) {
      RCC(rc, finish, _handshake_output_fill(ws));
    }
    ssize_t tow = iwxstr_size(ws->output);
    while (tow > 0) {
      ssize_t len = pa->write(pa, (void*) iwxstr_ptr(ws->output), tow);
      if (len == 0) {
        ret = -1;
        goto finish;
      } else if (len < 0) {
        if (errno == EINTR) {
          continue;
        } else if (errno != EAGAIN) {
          rc = iwrc_set_errno(IW_ERROR_IO_ERRNO, errno);
        }
        goto finish;
      } else {
        iwxstr_shift(ws->output, len);
        tow -= len;
      }
    }
    ws->state |= _STATE_HANDSHAKE_SEND;
  } else if (!(ws->state & _STATE_HANDSHAKE_RECV)) {  // Recieve response
    ret = IWN_POLLIN;
    uint8_t buf[1024];
    while (1) {
      ssize_t len = pa->read(pa, buf, sizeof(buf));
      if (len == 0) {
        ret = -1;
        goto finish;
      } else if (len < 0) {
        if (errno == EINTR) {
          continue;
        } else if (errno != EAGAIN) {
          rc = iwrc_set_errno(IW_ERROR_IO_ERRNO, errno);
        }
        goto finish;
      }
      if (!(ws->state & _STATE_HANDSHAKE_RECV)) {
        RCC(rc, finish, iwxstr_cat(ws->input, buf, len));
        if (iwxstr_size(ws->input) > (size_t) 1024 * 1024) {
          rc = WS_ERROR_HANDSHAKE;
          goto finish;
        }
        if (strstr(iwxstr_ptr(ws->input), "\r\n\r\n")) {
          ws->state |= _STATE_HANDSHAKE_RECV;
          char *p = iwn_strcasestr(iwxstr_ptr(ws->input), "sec-websocket-accept:");
          if (!p) {
            rc = WS_ERROR_HANDSHAKE_CLIENT_KEY;
            goto finish;
          }
          p += sizeof("sec-websocket-accept:") - 1;
          while (*p && iwchars_is_blank(*p)) p++;
          char *q = strstr(p, "\r\n");
          if (!q || !_handshake_validate_accept_key(ws, p, q - p)) {
            rc = WS_ERROR_HANDSHAKE_CLIENT_KEY;
            goto finish;
          }
          if (!(ws->flags & _FLAG_NO_NETWORK)) {
            RCC(rc, finish, _make_tcp_nodelay(ws->fd));
          }
        }
      }
    }
  }

finish:
  if (rc) {
    iwlog_ecode_error(rc, "ws | state=%d input=%s output=%s", ws->state,
                      iwxstr_size(ws->input) ? iwxstr_ptr(ws->input) : "",
                      iwxstr_size(ws->output) ? iwxstr_ptr(ws->output) : "");
    ret = -1;
  } else if (ws->state & _STATE_HANDSHAKE_RECV) {
    if (ws->spec.on_connected) {
      ws->spec.on_connected((void*) ws);
    }
  }
  return ret;
}

static int64_t _on_poller_adapter_event(struct iwn_poller_adapter *pa, void *user_data, uint32_t events) {
  struct iwn_ws_client *ws = user_data;
  int64_t ret = 0;

  pthread_mutex_lock(&ws->mtx);

  if (ws->pa != pa) {
    ws->pa = pa;
  }

  if (IW_UNLIKELY(!(ws->state & _STATE_HANDSHAKE_RECV))) {
    ret = _on_handshake_event(pa, user_data, events);
    if (ret == -1 || !(ws->state & _STATE_HANDSHAKE_RECV)) {
      goto finish;
    }
  }
  if (wslay_event_want_write(ws->wsl) && wslay_event_send(ws->wsl) < 0) {
    goto finish;
  }
  if (wslay_event_want_read(ws->wsl) && wslay_event_recv(ws->wsl) < 0) {
    goto finish;
  }

  if (wslay_event_want_read(ws->wsl)) {
    ret |= IWN_POLLIN;
  }
  if (wslay_event_want_write(ws->wsl)) {
    ret |= IWN_POLLOUT;
  }

finish:
  pthread_mutex_unlock(&ws->mtx);
  return ret == 0 ? -1 : ret;
}

static void _on_poller_adapter_dispose(struct iwn_poller_adapter *pa, void *user_data);

static iwrc _ws_connect(struct iwn_ws_client *ws) {
  iwrc rc = 0;
  const struct iwn_ws_client_spec *spec = &ws->spec;

  ws->state = 0;
  iwxstr_clear(ws->output);
  iwxstr_clear(ws->input);
  if (ws->wsl) {
    wslay_event_context_free(ws->wsl);
    ws->wsl = 0;
  }

  // Now do the initial handshake
  RCC(rc, finish, _connect(ws, (spec->flags & WS_CONNECT_ASYNC), &ws->fd));


  RCC(rc, finish, _wslayrc(wslay_event_context_client_init(&ws->wsl, &(struct wslay_event_callbacks) {
    .recv_callback = _wslay_event_recv_callback,
    .send_callback = _wslay_event_send_callback,
    .on_msg_recv_callback = _wslay_event_on_msg_recv_callback,
    .genmask_callback = _wslay_genmask_callback
  }, ws)));

  if (ws->flags & _FLAG_SECURE) {
    RCC(rc, finish, iwn_brssl_client_poller_adapter(&(struct iwn_brssl_client_poller_adapter_spec) {
      .poller = spec->poller,
      .host = ws->host,
      .on_event = _on_poller_adapter_event,
      .on_dispose = _on_poller_adapter_dispose,
      .user_data = ws,
      .timeout_sec = spec->timeout_sec,
      .events = IWN_POLLOUT,
      .events_mod = IWN_POLLET,
      .fd = ws->fd,
      .verify_peer = spec->flags & WS_VERIFY_PEER,
      .verify_host = spec->flags & WS_VERIFY_HOST
    }));
  } else {
    RCC(rc, finish,
        iwn_direct_poller_adapter(spec->poller, ws->fd,
                                  _on_poller_adapter_event,
                                  _on_poller_adapter_dispose,
                                  ws, IWN_POLLOUT, IWN_POLLET,
                                  spec->timeout_sec));
  }

finish:
  if (rc) {
    if (ws->fd > -1) {
      shutdown(ws->fd, SHUT_RDWR);
      close(ws->fd);
    }
  }
  return rc;
}

static void _ws_dispose(struct iwn_ws_client *ws) {
  if (__sync_bool_compare_and_swap(&ws->dispose_cas, false, true)) {
    if (ws->spec.on_dispose) {
      ws->spec.on_dispose(&ws->ctx);
    }
  }
}

bool iwn_ws_client_is_can_destroy(struct iwn_ws_client *ws) {
  return ws && ws->dispose_cas;
}

bool iwn_ws_client_destroy(struct iwn_ws_client *ws) {
  if (ws && ws->dispose_cas) {
    _ws_destroy(ws);
    return true;
  } else {
    return false;
  }
}

static void _ws_reconnect(void *d) {
  struct iwn_ws_client *ws = d;
  if (ws->reconnect_attempt++ < ws->spec.reconnect_attempts_num) {
    iwrc rc = _ws_connect(ws);
    if (!rc) {
      ws->reconnect_attempt = 0;
      return;
    } else {
      iwlog_ecode_error3(rc);
    }
  }
  _on_poller_adapter_dispose(ws->pa, ws);
}

static void _ws_reconnect_cancel(void *d) {
  struct iwn_ws_client *ws = d;
  _ws_dispose(ws);
}

static void _on_poller_adapter_dispose(struct iwn_poller_adapter *pa, void *user_data) {
  struct iwn_ws_client *ws = user_data;
  pthread_mutex_unlock(&ws->mtx);
  ws->pa = 0;
  pthread_mutex_unlock(&ws->mtx);
  if (  ws->close_cas
     || ws->wsl == 0
     || wslay_event_get_close_received(ws->wsl)
     || wslay_event_get_close_sent(ws->wsl)
     || ws->reconnect_attempt >= ws->spec.reconnect_attempts_num) {
    _ws_dispose(ws);
  } else {
    // Try reconnect
    if (iwn_schedule(&(struct iwn_scheduler_spec) {
      .user_data = ws,
      .poller = ws->spec.poller,
      .timeout_ms = (uint32_t) ws->spec.reconnect_attempt_pause_sec * 1000,
      .on_cancel = _ws_reconnect_cancel,
      .task_fn = _ws_reconnect
    })) {
      _ws_dispose(ws);
    }
  }
}

static bool _write(struct iwn_ws_client *ws, const void *buf, size_t buf_len, enum wslay_opcode opc) {
  if (!ws || !buf) {
    return false;
  }
  if (buf_len == 0) {
    return true;
  }
  bool ret = false;
  pthread_mutex_lock(&ws->mtx);
  if (wslay_event_queue_msg(ws->wsl, &(struct wslay_event_msg) {
    .opcode = opc,
    .msg = (void*) buf,
    .msg_length = buf_len
  })) {
    pthread_mutex_unlock(&ws->mtx);
    return false;
  }
  if (ws->pa) {
    ret = 0 == ws->pa->arm(ws->pa, IWN_POLLOUT);
  }
  pthread_mutex_unlock(&ws->mtx);
  return ret;
}

struct write_fd_ctx {
  const void *buf;
  size_t      buf_len;
  enum wslay_opcode opc;
  bool ret;
};

static void _write_fd_probe(struct iwn_poller *p, void *slot_user_data, void *fn_user_data) {
  struct iwn_poller_adapter *pa = slot_user_data;
  struct iwn_ws_client *ws = pa->user_data; // It is a struct iwn_poller_adapter->user_data actually
  struct write_fd_ctx *ctx = fn_user_data;
  ctx->ret = _write(ws, ctx->buf, ctx->buf_len, ctx->opc);
}

static bool _write_fd(struct iwn_poller *p, int fd, const void *buf, size_t buf_len, enum wslay_opcode opc) {
  struct write_fd_ctx ctx = {
    .buf = buf,
    .buf_len = buf_len,
    .opc = opc
  };
  iwn_poller_probe(p, fd, _write_fd_probe, &ctx);
  return ctx.ret;
}

bool iwn_ws_client_write_text(struct iwn_ws_client *ws, const void *buf, size_t buf_len) {
  return _write(ws, buf, buf_len, WSLAY_TEXT_FRAME);
}

bool iwn_ws_client_write_text_fd(struct iwn_poller *p, int fd, const void *buf, size_t buf_len) {
  return _write_fd(p, fd, buf, buf_len, WSLAY_TEXT_FRAME);
}

bool iwn_ws_client_write_json(struct iwn_ws_client *ws, struct jbl_node *json) {
  bool rv = false;
  struct iwxstr *xstr = iwxstr_create_empty();
  if (xstr) {
    if (!jbn_as_json(json, jbl_xstr_json_printer, xstr, 0)) {
      rv = iwn_ws_client_write_text(ws, iwxstr_ptr(xstr), iwxstr_len(xstr));
    }
    iwxstr_destroy(xstr);
  }
  return rv;
}

bool iwn_ws_client_write_json_fd(struct iwn_poller *p, int fd, struct jbl_node *json) {
  bool rv = false;
  struct iwxstr *xstr = iwxstr_create_empty();
  if (xstr) {
    if (!jbn_as_json(json, jbl_xstr_json_printer, xstr, 0)) {
      rv = iwn_ws_client_write_text_fd(p, fd, iwxstr_ptr(xstr), iwxstr_len(xstr));
    }
    iwxstr_destroy(xstr);
  }
  return rv;
}

bool iwn_ws_client_write_binary(struct iwn_ws_client *ws, const void *buf, size_t buf_len) {
  return _write(ws, buf, buf_len, WSLAY_BINARY_FRAME);
}

bool iwn_ws_client_write_binary_fd(struct iwn_poller *p, int fd, const void *buf, size_t buf_len) {
  return _write_fd(p, fd, buf, buf_len, WSLAY_BINARY_FRAME);
}

bool iwn_ws_client_ping(struct iwn_ws_client *ws, const void *buf, size_t buf_len) {
  return _write(ws, buf, buf_len, WSLAY_PING);
}

bool iwn_ws_client_ping_fd(struct iwn_poller *p, int fd, const void *buf, size_t buf_len) {
  return _write_fd(p, fd, buf, buf_len, WSLAY_PING);
}

iwrc iwn_ws_client_open(const struct iwn_ws_client_spec *spec, struct iwn_ws_client **out_ws) {
  if (__sync_bool_compare_and_swap(&_initialized, false, true)) {
    RCR(iwlog_register_ecodefn(_ecodefn));
  }
  if (out_ws) {
    *out_ws = 0;
  }
  if (!spec || !spec->url || !spec->poller || !spec->on_message) {
    return IW_ERROR_INVALID_ARGS;
  }

  iwrc rc = 0;

  struct iwn_ws_client *ws = calloc(1, sizeof(*ws));
  if (!ws) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  memcpy(&ws->spec, spec, sizeof(*spec));
  ws->ctx.poller = spec->poller;
  ws->ctx.user_data = spec->user_data;
  ws->ctx.ws = ws;
  ws->fd = -1;

  if (!ws->spec.reconnect_attempt_pause_sec) {
    ws->spec.reconnect_attempt_pause_sec = 5;
  }

  pthread_mutexattr_t attr;
  pthread_mutexattr_init(&attr);
  pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
  pthread_mutex_init(&ws->mtx, &attr);
  pthread_mutexattr_destroy(&attr);

  RCB(finish, ws->output = iwxstr_create_empty());
  RCB(finish, ws->input = iwxstr_create_empty());
  RCB(finish, ws->urlbuf = strdup(spec->url));

  struct iwn_url u;
  if (iwn_url_parse(&u, ws->urlbuf) == -1) {
    iwlog_error("Failed to parse url: %s", spec->url);
    rc = IW_ERROR_INVALID_VALUE;
    goto finish;
  }

  ws->host = u.host;
  ws->port = u.port;
  ws->query = u.query;
  ws->scheme = u.scheme;

  if (u.scheme && strcmp("wss", u.scheme) == 0) {
    ws->flags |= _FLAG_SECURE;
  }
  if (ws->port < 1) {
    ws->port = (ws->flags & _FLAG_SECURE) ? 443 : 80;
  }

  if (!u.path) {
    RCB(finish, ws->path = strdup("/"));
  } else if (strcmp("socket", u.scheme) == 0) {
    ws->flags |= _FLAG_NO_NETWORK;
    if (u.host == u.path - 1) {
      *(u.path - 1) = '/'; // WARNING: Dependence of iwn_url_parse implementation
    }
    RCB(finish, ws->path = strdup(spec->path_ext ? spec->path_ext : "/"));
  } else {
    size_t len = strlen(u.path);
    RCB(finish, ws->path = malloc(len + 2));
    ws->path[0] = '/';
    memcpy(ws->path + 1, u.path, len + 1);
  }

  rc = _ws_connect(ws);

finish:
  if (rc) {
    _ws_destroy(ws);
  } else {
    *out_ws = ws;
  }
  return rc;
}

static void _close_fd_probe(struct iwn_poller *p, void *slot_user_data, void *fn_user_data) {
  struct iwn_poller_adapter *pa = slot_user_data;
  struct iwn_ws_client *ws = pa->user_data; // It is a struct iwn_poller_adapter->user_data actually
  iwn_ws_client_close(ws);
}

void iwn_ws_client_close_by_fd(struct iwn_poller *p, int fd) {
  iwn_poller_probe(p, fd, _close_fd_probe, 0);
}

void iwn_ws_client_close(struct iwn_ws_client *ws) {
  if (__sync_bool_compare_and_swap(&ws->close_cas, false, true)) {
    iwn_poller_remove(ws->spec.poller, ws->fd);
  }
}

static void _send_close_fd_probe(struct iwn_poller *p, void *slot_user_data, void *fn_user_data) {
  struct iwn_poller_adapter *pa = slot_user_data;
  struct iwn_ws_client *ws = pa->user_data; // It is a struct iwn_poller_adapter->user_data actually
  iwn_ws_client_send_close(ws);
}

void iwn_ws_client_send_close_by_fd(struct iwn_poller *p, int fd) {
  iwn_poller_probe(p, fd, _send_close_fd_probe, 0);
}

bool iwn_ws_client_send_close(struct iwn_ws_client *ws) {
  bool ret = false;
  if (ws) {
    pthread_mutex_lock(&ws->mtx);
    ret = wslay_event_queue_close(ws->wsl, 0, 0, 0) == 0;
    pthread_mutex_unlock(&ws->mtx);
  }
  return ret;
}

int iwn_ws_client_fd_get(struct iwn_ws_client *ws) {
  return ws ? ws->fd : -1;
}

static const char* _ecodefn(locale_t locale, uint32_t ecode) {
  if (ecode <= _WS_ERROR_START || ecode >= _WS_ERROR_END) {
    return 0;
  }
  switch (ecode) {
    case WS_ERROR_INVALID_URL:
      return "Websocket invalid URL (WS_ERROR_INVALID_URL)";
    case WS_ERROR_PEER_CONNECT:
      return "Websocket peer connection failed (WS_ERROR_PEER_CONNECT)";
    case WS_ERROR_HANDSHAKE:
      return "Websocket handshake error (WS_ERROR_HANDSHAKE)";
    case WS_ERROR_HANDSHAKE_CLIENT_KEY:
      return "Websocket handshake client key validation error (WS_ERROR_HANDSHAKE_CLIENT_KEY)";
    case WS_ERROR_CHANNEL_CLOSED:
      return "Websocket communication channel is closed (WS_ERROR_CHANNEL_CLOSED)";
    case WS_ERROR:
      return "Websocket generic error (WS_ERROR)";
  }
  return 0;
}

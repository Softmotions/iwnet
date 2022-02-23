#include "ws_client.h"

#include "poller.h"
#include "poller/direct_poller_adapter.h"
#include "bearssl/bearssl_hash.h"
#include "ssl/brssl_poller_adapter.h"
#include "utils/base64.h"
#include "utils/url.h"
#include "utils/utils.h"
#include "wslay/wslay.h"

#include <iowow/iwlog.h>
#include <iowow/iwxstr.h>
#include <iowow/iwutils.h>

#include <pthread.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <ctype.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <assert.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <netinet/in.h>

#define _STATE_HANDSHAKE_SEND 0x01U
#define _STATE_HANDSHAKE_RECV 0x02U

struct iwn_ws_client {
  struct iwn_ws_client_ctx   ctx;
  struct iwn_ws_client_spec  spec;
  struct iwn_poller_adapter *pa;
  char *host;
  char *path;
  char *query;
  char *urlbuf;
  wslay_event_context_ptr wc;
  IWXSTR *output;
  IWXSTR *input;
  pthread_mutex_t mtx;
  int     port;
  int     fd;
  uint8_t state;
  bool    secure;
  volatile bool dispose_cas;
  char client_key[32];
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

static void _destroy(struct iwn_ws_client *ws) {
  if (!ws) {
    return;
  }
  if (ws->fd > -1) {
    close(ws->fd);
  }
  free(ws->path);
  free(ws->urlbuf);
  wslay_event_context_free(ws->wc);
  iwxstr_destroy(ws->output);
  iwxstr_destroy(ws->input);
  pthread_mutex_destroy(&ws->mtx);
  free(ws);
}

static iwrc _connect(const char *host, int port_, int *out_fd) {
  assert(host && out_fd);

  *out_fd = 0;

  char nbuf[64];
  snprintf(nbuf, sizeof(nbuf), "%d", port_);
  char *port = nbuf;

  iwrc rc = 0;
  int fd = -1, rci;
  struct addrinfo *si, *p, hints = {
    .ai_family   = PF_UNSPEC,
    .ai_socktype = SOCK_STREAM
  };
  rci = getaddrinfo(host, port, &hints, &si);
  if (rci) {
    iwlog_ecode_error(WS_ERROR_PEER_CONNECT, "ws | %s", gai_strerror(rci));
    return WS_ERROR_PEER_CONNECT;
  }
  for (p = si; p; p = p->ai_next) {
    char tmp[INET6_ADDRSTRLEN + 50];
    struct sockaddr *sa = p->ai_addr;
    void *addr = 0;

    if (sa->sa_family == AF_INET) {
      addr = &((struct sockaddr_in*) sa)->sin_addr;
    } else if (sa->sa_family == AF_INET6) {
      addr = &((struct sockaddr_in6*) sa)->sin6_addr;
    }
    if (!addr) {
      iwlog_ecode_error(WS_ERROR_PEER_CONNECT, "ws | Unknown address family: %d", (int) sa->sa_family);
      rc = WS_ERROR_PEER_CONNECT;
      goto finish;
    }
    inet_ntop(p->ai_family, addr, tmp, sizeof(tmp));
    fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
    if (fd < 0) {
      iwlog_warn("ws | Error opening socket %s:%s %s %s", host, port, tmp, strerror(errno));
      continue;
    }
    if (connect(fd, p->ai_addr, p->ai_addrlen) < 0) {
      iwlog_warn("ws | Error connecting %s:%s %s %s", host, port, tmp, strerror(errno));
      close(fd);
      continue;
    }
    break;
  }
  if (p) {
    *out_fd = fd;
  } else {
    rc = WS_ERROR_PEER_CONNECT;
  }

finish:
  freeaddrinfo(si);
  return rc;
}

static iwrc _make_non_blocking(int fd) {
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

static iwrc _make_tcp_nodelay(int fd) {
  int val = 1;
  if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &val, (socklen_t) sizeof(val)) == -1) {
    return iwrc_set_errno(IW_ERROR_ERRNO, errno);
  } else {
    return 0;
  }
}

static void _on_poller_adapter_dispose(struct iwn_poller_adapter *pa, void *user_data) {
  struct iwn_ws_client *ws = user_data;
  if (__sync_bool_compare_and_swap(&ws->dispose_cas, false, true)) {
    pthread_mutex_lock(&ws->mtx);
    ws->fd = -1;
    ws->spec.on_dispose(&ws->ctx);
    pthread_mutex_unlock(&ws->mtx);
    _destroy(ws);
  }
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
  RCR(iwxstr_printf(
        ws->output,
        "GET %s%s%s HTTP/1.1\r\n"
        "Host: %s:%d\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-Websocket-Key: %s\r\n"
        "Sec-Websocket-Version: 13\r\n"
        "\r\n",
        ws->path, (ws->query ? "?" : ""), (ws->query ? ws->query : ""),
        ws->host, ws->port,
        ws->client_key));
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
        if (iwxstr_size(ws->input) > 1024 * 1024) {
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
          while (*p && isblank(*p)) p++;
          char *q = strstr(p, "\r\n");
          if (!q || !_handshake_validate_accept_key(ws, p, q - p)) {
            rc = WS_ERROR_HANDSHAKE_CLIENT_KEY;
            goto finish;
          }
          RCC(rc, finish, _make_tcp_nodelay(ws->fd));
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
  } else if ((ws->state & _STATE_HANDSHAKE_RECV) && ws->spec.on_connected) {
    ws->spec.on_connected((void*) ws);
  }
  return ret;
}

static int64_t _on_poller_adapter_event(struct iwn_poller_adapter *pa, void *user_data, uint32_t events) {
  struct iwn_ws_client *ws = user_data;
  int64_t ret = 0;

  if (ws->pa != pa) {
    ws->pa = pa;
  }

  pthread_mutex_lock(&ws->mtx);

  if (IW_UNLIKELY(!(ws->state & _STATE_HANDSHAKE_RECV))) {
    ret = _on_handshake_event(pa, user_data, events);
    goto finish;
  }
  if (wslay_event_want_write(ws->wc) && wslay_event_send(ws->wc) < 0) {
    goto finish;
  }
  if (wslay_event_want_read(ws->wc) && wslay_event_recv(ws->wc) < 0) {
    goto finish;
  }

  if (wslay_event_want_read(ws->wc)) {
    ret |= IWN_POLLIN;
  }
  if (wslay_event_want_write(ws->wc)) {
    ret |= IWN_POLLOUT;
  }

finish:
  pthread_mutex_unlock(&ws->mtx);
  return ret == 0 ? -1 : ret;
}

static ssize_t _wslay_event_recv_callback(
  wslay_event_context_ptr ctx,
  uint8_t                *buf,
  size_t                  len,
  int                     flags,
  void                   *user_data
  ) {
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
      wslay_event_set_error(ws->wc, WSLAY_ERR_WOULDBLOCK);
    } else {
      wslay_event_set_error(ws->wc, WSLAY_ERR_CALLBACK_FAILURE);
    }
  } else if (rci == 0) {
    errno = EIO;
    rci = -1;
  }
  return rci;
}

static ssize_t _wslay_event_send_callback(
  wslay_event_context_ptr ctx,
  const uint8_t          *buf,
  size_t                  len,
  int                     flags,
  void                   *user_data
  ) {
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
      wslay_event_set_error(ws->wc, WSLAY_ERR_WOULDBLOCK);
    } else {
      wslay_event_set_error(ws->wc, WSLAY_ERR_CALLBACK_FAILURE);
    }
  } else if (rci == 0) {
    errno = EIO;
    rci = -1;
  }
  return rci;
}

static void _wslay_event_on_msg_recv_callback(
  wslay_event_context_ptr                   ctx,
  const struct wslay_event_on_msg_recv_arg *arg,
  void                                     *user_data
  ) {
  struct iwn_ws_client *ws = user_data;
  if (wslay_is_ctrl_frame(arg->opcode)) {
    return;
  }
  if (arg->msg_length > 0) {
    ws->spec.on_message((void*) arg->msg, arg->msg_length, &ws->ctx);
  }
}

static int _wslay_genmask_callback(
  wslay_event_context_ptr ctx, uint8_t *buf, size_t len,
  void *user_data
  ) {
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

bool iwn_ws_client_write_text(struct iwn_ws_client *ws, const void *buf, size_t buf_len) {
  if (!ws || !buf) {
    return false;
  }
  if (buf_len == 0) {
    return true;
  }
  pthread_mutex_lock(&ws->mtx);
  if (wslay_event_queue_msg(ws->wc, &(struct wslay_event_msg) {
    .opcode = WSLAY_TEXT_FRAME,
    .msg = (void*) buf,
    .msg_length = buf_len
  })) {
    pthread_mutex_unlock(&ws->mtx);
    return false;
  }
  pthread_mutex_unlock(&ws->mtx);
  return 0 == ws->pa->arm(ws->pa, IWN_POLLOUT);
}

iwrc iwn_ws_client_open(const struct iwn_ws_client_spec *spec, struct iwn_ws_client **out_ws) {
  if (__sync_bool_compare_and_swap(&_initialized, false, true)) {
    RCR(iwlog_register_ecodefn(_ecodefn));
  }
  if (out_ws) {
    *out_ws = 0;
  }
  if (!spec || !spec->url || !spec->poller || !spec->on_dispose || !spec->on_message) {
    return IW_ERROR_INVALID_ARGS;
  }

  iwrc rc = 0;
  char *ptr;

  struct iwn_ws_client *ws = calloc(1, sizeof(*ws));
  if (!ws) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  memcpy(&ws->spec, spec, sizeof(*spec));
  ws->ctx.poller = spec->poller;
  ws->ctx.user_data = spec->user_data;
  ws->ctx.ws = ws;
  ws->fd = -1;

  pthread_mutexattr_t attr;
  pthread_mutexattr_init(&attr);
  pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
  pthread_mutex_init(&ws->mtx, &attr);
  pthread_mutexattr_destroy(&attr);

  RCB(finish, ws->output = iwxstr_new());
  RCB(finish, ws->input = iwxstr_new());
  RCB(finish, ws->urlbuf = strdup(spec->url));

  struct iwn_url u;
  if (iwn_url_parse(&u, ws->urlbuf) == -1) {
    iwlog_error("Failed to parse url: %s", ws->urlbuf);
    rc = IW_ERROR_FAIL;
    goto finish;
  }
  ws->host = u.host;
  ws->path = u.path;
  ws->port = u.port;
  ws->query = u.query;

  if (!ws->path) {
    RCB(finish, ws->path = strdup("/"));
  } else {
    RCB(finish, ws->path = malloc(strlen(u.path) + 2));
    ws->path[0] = '/';
    memcpy(ws->path + 1, u.path, strlen(u.path) + 1);
  }

  ptr = u.scheme;
  if (ptr) {
    if (strcmp("wss", ptr) == 0) {
      ws->secure = true;
    }
  }
  if (ws->port < 1) {
    ws->port = ws->secure ? 443 : 80;
  }

  // Now do the initial handshake
  RCC(rc, finish, _connect(ws->host, ws->port, &ws->fd));
  RCC(rc, finish, _make_non_blocking(ws->fd));

  RCC(rc, finish, _wslayrc(wslay_event_context_client_init(&ws->wc, &(struct wslay_event_callbacks) {
    .recv_callback = _wslay_event_recv_callback,
    .send_callback = _wslay_event_send_callback,
    .on_msg_recv_callback = _wslay_event_on_msg_recv_callback,
    .genmask_callback = _wslay_genmask_callback
  }, ws)));

  if (ws->secure) {
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
      .verify_peer = spec->flags & IWN_WS_VERIFY_PEER,
      .verify_host = spec->flags & IWN_WS_VERIFY_HOST
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
    if (out_ws) {
      *out_ws = 0;
    }
    _destroy(ws);
  }
  return rc;
}

void iwn_ws_client_close(struct iwn_ws_client *ws) {
  iwn_poller_remove(ws->spec.poller, ws->fd);
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

#include "iwn_grpc_client.h"
#include "iwn_url.h"

#include <iowow/iwrefs.h>
#include <iowow/iwlog.h>
#include <iowow/iwpool.h>
#include <iowow/iwutils.h>
#include <iowow/iwxstr.h>

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

struct iwn_grpc_client {
  struct iwref_holder ref;
  struct iwn_poller  *poller;
  struct iwpool      *pool;
  struct iwn_poller_adapter *pa;
  struct hive_session       *sess;
  struct hive_callbacks      hive_callbacks;
  struct hive_options       *hive_options;
  struct iwxstr *input_buf;
  struct iwxstr *output_buf;
  struct _rx     rx;
  struct iwn_grpc_client_spec spec;
  pthread_mutex_t mtx;
  struct iwn_url  url;
  int      fd; ///< Connection file descriptor
  unsigned flags;
  volatile bool close_pending;
};

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

static void _client_destroy(void *d) {
  struct iwn_grpc_client *client = d;
  if (client->spec.on_destroy) {
    struct iwn_grpc_client_ctx ctx;
    iwn_grpc_client_ctx_init(client, &ctx);
    client->spec.on_destroy(&ctx);
  }
  iwxstr_destroy(client->input_buf);
  iwxstr_destroy(client->output_buf);
  pthread_mutex_destroy(&client->mtx);
  if (client->hive_options) {
    hive_options_free(client->hive_options);
  }
  if (client->sess) {
    hive_session_free(client->sess);
  }
  iwpool_destroy(client->pool);
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

static iwrc _client_connect(struct iwn_grpc_client *client) {
  iwrc rc = 0;

  iwxstr_clear(client->input_buf);
  iwxstr_clear(client->output_buf);

  if (client->sess) {
    hive_session_free(client->sess);
    client->sess = 0;
  }

  RCC(rc, finish, _connect(client, &client->fd));
  _rx_init(&client->rx);


finish:
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

static int _hcb_on_stream_close(
  hive_session_t *session,
  uint32_t        stream_id,
  uint32_t        error_code,
  void           *user_data) {
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

IW_INLINE void _hive_pre_init(struct iwn_grpc_client *client) {
  struct hive_callbacks *cbs = &client->hive_callbacks;
  cbs->on_begin_headers = _hcb_on_begin_headers;
  cbs->on_header = _hcb_on_header;
  cbs->on_headers_complete = _hcb_on_headers_complete;
  cbs->on_data_chunk = _hcb_on_data_chunk;
  cbs->on_stream_close = _hcb_on_stream_close;
  cbs->on_goaway = _hcb_on_goaway;
  cbs->on_connection_error = _hcb_on_connection_error;
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
    // TODO: Disconnect
    iwref_unref(&client->ref);
  }
}

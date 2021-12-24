#include "http_server.h"
#include "poller_adapter.h"
#include "poller/direct_poller_adapter.h"
#include "ssl/brssl_poller_adapter.h"

#include <iowow/iwlog.h>
#include <iowow/iwpool.h>

#include <assert.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <pthread.h>

#define CLIENT_INIT  0
#define CLIENT_READ  1
#define CLIENT_WRITE 2
#define CLIENT_NOP   3

struct server {
  struct iwn_http_server_spec spec;
  int fd;
  int refs;
  pthread_mutex_t mtx;
  IWPOOL *pool;
  bool    https;
};

struct client {
  IWPOOL *pool;
  struct server *server;
  int fd;
  int state;
};


static struct server* _server_ref(struct server *server);
static void _server_unref(struct server *server);

///////////////////////////////////////////////////////////////////////////
//								              Client                                   //
///////////////////////////////////////////////////////////////////////////

static int64_t _client_on_poller_adapter_event(struct iwn_poller_adapter *pa, void *user_data, uint32_t events) {
  return 0;
}

static void _client_destroy(struct client *client) {
  if (!client) {
    return;
  }
  if (client->fd > -1) {
    close(client->fd);
  }
  if (client->server) {
    _server_unref(client->server);
  }
  iwpool_destroy(client->pool);
}

static void _client_on_poller_adapter_dispose(struct iwn_poller_adapter *pa, void *user_data) {
  struct client *client = user_data;
  _client_destroy(client);
}

static iwrc _client_accept(struct server *server, int fd) {
  iwrc rc = 0;
  IWPOOL *pool = iwpool_create_empty();
  if (!pool) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  struct client *client;
  RCA(client = iwpool_alloc(sizeof(*client), pool), finish);
  client->pool = pool;
  client->fd = fd;
  client->server = _server_ref(server);

  int flags = fcntl(fd, F_GETFL, 0);
  RCN(finish, flags);
  RCN(finish, fcntl(fd, F_SETFL, flags | O_NONBLOCK));

  if (server->https) {
    RCC(rc, finish, iwn_brssl_server_poller_adapter(&(struct iwn_brssl_server_poller_adapter_spec) {
      .certs_data = server->spec.certs_data,
      .certs_data_in_buffer = server->spec.certs_data_in_buffer,
      .certs_data_len = server->spec.certs_data_len,
      .events = IWN_POLLIN,
      .events_mod = IWN_POLLET,
      .fd = fd,
      .on_dispose = _client_on_poller_adapter_dispose,
      .on_event = _client_on_poller_adapter_event,
      .poller = server->spec.poller,
      .private_key = server->spec.private_key,
      .private_key_in_buffer = server->spec.private_key_in_buffer,
      .private_key_len = server->spec.private_key_len,
      .timeout_sec = server->spec.connection_timeout_sec,
      .user_data = client,
    }));
  } else {
    RCC(rc, finish,
        iwn_direct_poller_adapter(
          server->spec.poller, fd,
          _client_on_poller_adapter_event,
          _client_on_poller_adapter_dispose,
          client, IWN_POLLIN, IWN_POLLET,
          server->spec.connection_timeout_sec));
  }

finish:
  if (rc) {
    if (client) {
      _client_destroy(client);
    } else {
      iwpool_destroy(pool);
    }
  }

  return rc;
}

///////////////////////////////////////////////////////////////////////////
//								             Server                                    //
///////////////////////////////////////////////////////////////////////////

static void _server_destroy(struct server *server) {
  if (!server) {
    return;
  }
  if (server->fd > -1) {
    close(server->fd);
  }
  pthread_mutex_destroy(&server->mtx);
  iwpool_destroy(server->pool);
}

static int64_t _server_on_ready(const struct iwn_poller_task *t, uint32_t events) {
  struct server *server = t->user_data;
  int sfd = 0;

  do {
    sfd = accept(t->fd, 0, 0);
    if (sfd == -1) {
      break;
    }
    iwrc rc = _client_accept(server, sfd);
    if (rc) {
      iwlog_ecode_error3(rc);
    }
  } while (1);

  return 0;
}

static struct server* _server_ref(struct server *server) {
  pthread_mutex_lock(&server->mtx);
  if (server->refs == 0) {
    iwlog_ecode_error(IW_ERROR_ASSERTION, "Server instance fd: %d is already disposed", server->fd);
    assert(server->refs);
  } else {
    ++server->refs;
  }
  pthread_mutex_unlock(&server->mtx);
  return server;
}

static void _server_unref(struct server *server) {
  int refs;
  pthread_mutex_lock(&server->mtx);
  refs = --server->refs;
  pthread_mutex_unlock(&server->mtx);
  if (refs < 1) {
    _server_destroy(server);
  }
}

static void _server_on_dispose(const struct iwn_poller_task *t) {
  struct server *server = t->user_data;
  // TODO:
  _server_unref(server);
}

iwrc iwn_http_server_create(const struct iwn_http_server_spec *spec_, iwn_http_server_fd_t *out_fd) {
  iwrc rc = 0;
  *out_fd = 0;
  int optval;
  struct server *server;
  struct iwn_http_server_spec *spec;

  IWPOOL *pool = iwpool_create_empty();
  if (!pool) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  RCA(server = iwpool_calloc(sizeof(*server), pool), finish);
  memcpy(&server->mtx, &(pthread_mutex_t) PTHREAD_MUTEX_INITIALIZER, sizeof(server->mtx));
  server->pool = pool;
  spec = &server->spec;
  memcpy(spec, spec_, sizeof(*spec));

  if (!spec->poller) {
    rc = IW_ERROR_INVALID_ARGS;
    iwlog_ecode_error2(rc, "No poller specified");
    goto finish;
  }

  server->https = spec->certs_data && spec->certs_data_len && spec->private_key && spec->private_key_len;
  if (server->https) {
    spec->certs_data = iwpool_strndup(pool, spec->certs_data, spec->certs_data_len, &rc);
    RCGO(rc, finish);
    spec->private_key = iwpool_strndup(pool, spec->private_key, spec->private_key_len, &rc);
    RCGO(rc, finish);
  }

  if (!spec->port) {
    spec->port = server->https ? 8443 : 8080;
  }
  if (!spec->listen) {
    spec->listen = "localhost";
  }
  if (spec->connection_timeout_sec < 1) {
    spec->connection_timeout_sec = 30;
  }

  RCA(spec->listen = iwpool_strdup2(pool, spec->listen), finish);

  struct iwn_poller_task task = {
    .user_data  = server,
    .on_ready   = _server_on_ready,
    .on_dispose = _server_on_dispose,
    .events     = IWN_POLLIN,
    .events_mod = IWN_POLLET,
    .poller     = spec->poller
  };

  struct addrinfo hints = {
    .ai_socktype = SOCK_STREAM,
    .ai_family   = AF_UNSPEC,
    .ai_flags    = AI_PASSIVE | AI_NUMERICSERV
  };

  struct addrinfo *result, *rp;
  char port[32];
  snprintf(port, sizeof(port), "%d", spec->port);

  int rci = getaddrinfo(spec->listen, port, &hints, &result);
  if (rci != 0) {
    rc = IW_ERROR_FAIL;
    iwlog_error("Error getting local address and port: %s", gai_strerror(rci));
    goto finish;
  }

  optval = 1;
  for (rp = result; rp; rp = rp->ai_next) {
    task.fd = socket(rp->ai_family, rp->ai_socktype | SOCK_CLOEXEC, rp->ai_protocol);
    server->fd = task.fd;
    if (task.fd < 0) {
      continue;
    }
    if (setsockopt(task.fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &optval, sizeof(optval)) < 0) {
      iwlog_error("Error setsockopt: %s", strerror(errno));
    }
    if (bind(task.fd, rp->ai_addr, rp->ai_addrlen) == 0) {
      break;
    } else {
      iwlog_error("Error binding socket: %s", strerror(errno));
    }
    close(task.fd);
  }

  freeaddrinfo(result);
  if (!rp) {
    rc = iwrc_set_errno(IW_ERROR_ERRNO, errno);
    iwlog_ecode_error2(rc, "Could not find any suitable address to bind");
    goto finish;
  }
  RCN(finish, optval = fcntl(task.fd, F_GETFL, 0));
  RCN(finish, fcntl(task.fd, F_SETFL, optval | O_NONBLOCK));
  RCN(finish, listen(task.fd, 64)); // TODO: Make configurable

  rc = iwn_poller_add(&task);

finish:
  if (rc) {
    if (server) {
      _server_destroy(server);
    } else {
      iwpool_destroy(pool);
    }
  } else {
    *out_fd = server->fd;
  }
  return rc;
}

iwrc iwn_http_server_request_dispose(iwn_http_server_fd_t h) {
  iwrc rc = 0;

  return rc;
}

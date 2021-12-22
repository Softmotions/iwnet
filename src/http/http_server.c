#include "http_server.h"
#include "poller_adapter.h"
#include "poller/direct_poller_adapter.h"
#include "ssl/brssl_poller_adapter.h"

#include <iowow/iwlog.h>
#include <iowow/iwpool.h>

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

struct _server {
  struct iwn_http_server_spec spec;
  int     fd;
  IWPOOL *pool;
};

struct _client {
  int     fd;
  IWPOOL *pool;
};

///////////////////////////////////////////////////////////////////////////
//								              Client                                   //
///////////////////////////////////////////////////////////////////////////

static int64_t _client_on_poller_adapter_event(struct iwn_poller_adapter *pa, void *user_data, uint32_t events) {
  return 0;
}

static void _client_on_poller_adapter_dispose(struct iwn_poller_adapter *pa, void *user_data) {
}

static void _client_destroy(struct _client *client) {
  if (!client) {
    return;
  }
  if (client->fd > -1) {
    close(client->fd);
  }
  iwpool_destroy(client->pool);
}

static iwrc _client_accept(struct _server *server, int fd) {
  iwrc rc = 0;
  IWPOOL *pool = iwpool_create_empty();
  if (!pool) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  struct _client *client;
  RCA(client = iwpool_alloc(sizeof(*client), pool), finish);
  client->pool = pool;
  client->fd = fd;

  int flags = fcntl(fd, F_GETFL, 0);
  RCN(finish, flags);
  RCN(finish, fcntl(fd, F_SETFL, flags | O_NONBLOCK));

  if (server->spec.https) {
  
    

  } else {

    RCC(rc, finish,
        iwn_direct_poller_adapter_create(
          server->spec.poller, fd,
          _client_on_poller_adapter_event,
          _client_on_poller_adapter_dispose,
          client, EPOLLIN, EPOLLET,
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

static void _server_destroy(struct _server *server) {
  if (!server) {
    return;
  }
  if (server->fd > -1) {
    close(server->fd);
  }
  iwpool_destroy(server->pool);
}

static int64_t _server_on_ready(const struct iwn_poller_task *t, uint32_t events) {
  struct _server *server = t->user_data;
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

static void _server_on_dispose(const struct iwn_poller_task *t) {
  struct _server *srv = t->user_data;
  // TODO:
  _server_destroy(srv);
}

iwrc iwn_http_server_create(const struct iwn_http_server_spec *spec_, iwn_http_server_fd_t *out_fd) {
  iwrc rc = 0;
  *out_fd = 0;
  int optval;
  struct _server *server;
  struct iwn_http_server_spec *spec;

  IWPOOL *pool = iwpool_create_empty();
  if (!pool) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  RCA(server = iwpool_calloc(sizeof(*server), pool), finish);
  server->pool = pool;
  spec = &server->spec;
  memcpy(spec, spec_, sizeof(*spec));

  if (!spec->poller) {
    rc = IW_ERROR_INVALID_ARGS;
    iwlog_ecode_error2(rc, "No poller specified");
    goto finish;
  }
  if (!spec->port) {
    spec->port = spec->https ? 8443 : 8080;
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
    .events     = EPOLLIN,
    .events_mod = EPOLLET,
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

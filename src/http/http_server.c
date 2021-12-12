#include "http_server.h"
#include "poller_adapter.h"

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

struct iwn_http_server_impl {
  struct iwn_http_server_spec spec;
  int     fd;
  IWPOOL *pool;
};

static int64_t _on_poller_adapter_event(struct iwn_poller_adapter *pa, void *user_data, uint32_t events) {
  return 0;
}

static void _on_poller_adapter_dispose(struct iwn_poller_adapter *pa, void *user_data) {
}

static void _impl_destroy(struct iwn_http_server_impl **implp) {
  if (!implp) {
    return;
  }
  struct iwn_http_server_impl *impl = *implp;
  if (impl->fd > -1) {
    close(impl->fd);
  }
  if (impl->pool) {
    iwpool_destroy(impl->pool);
  }
  *implp = 0;
}

static int64_t _impl_on_ready(const struct iwn_poller_task *t, uint32_t events) {
  return events;
}

static void _impl_on_dispose(const struct iwn_poller_task *t) {
}

iwrc iwn_http_server_create(const struct iwn_http_server_spec *spec_, iwn_http_server_fd_t *out_fd) {
  iwrc rc = 0;
  *out_fd = 0;
  int optval;
  struct iwn_http_server_impl *impl;
  struct iwn_http_server_spec *spec;

  IWPOOL *pool = iwpool_create_empty();
  if (!pool) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  RCA(impl = iwpool_calloc(sizeof(*impl), pool), finish);
  impl->pool = pool;
  spec = &impl->spec;
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
  RCA(spec->listen = iwpool_strdup2(pool, spec->listen), finish);

  struct iwn_poller_task task = {
    .user_data  = impl,
    .on_ready   = _impl_on_ready,
    .on_dispose = _impl_on_dispose,
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
    impl->fd = task.fd;
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
    _impl_destroy(&impl);
  } else {
    *out_fd = impl->fd;
  }
  return rc;
}

iwrc iwn_http_server_request_dispose(iwn_http_server_fd_t h) {
  iwrc rc = 0;

  return rc;
}

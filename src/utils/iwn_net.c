#include "iwn_net.h"

#include <iowow/iwlog.h>

#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

iwrc iwn_port_is_bound(const char *listen, int port_, uint32_t flags, bool *out) {
  if (port_ < 1 || !listen || !out) {
    return IW_ERROR_INVALID_ARGS;
  }
  *out = true;

  struct addrinfo hints = {
    .ai_flags = AI_PASSIVE
  };
  if (flags & IWN_UDP) {
    hints.ai_socktype = SOCK_DGRAM;
  } else {
    hints.ai_socktype = SOCK_STREAM;
  }
  if (flags & IWN_IPV6) {
    hints.ai_family = AF_INET6;
  } else {
    hints.ai_family = AF_INET;
  }

  const int optval = 1;
  bool success = false;
  struct addrinfo *result, *rp;
  char port[32];
  snprintf(port, sizeof(port), "%d", port_);

  int rci = getaddrinfo(listen, port, &hints, &result);
  if (rci) {
    iwlog_error("Error getting local address and port: %s", gai_strerror(rci));
    return IW_ERROR_FAIL;
  }
  for (rp = result; rp && !success; rp = rp->ai_next) {
    int fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
    if (fd > 0) {
      setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
      if (bind(fd, rp->ai_addr, rp->ai_addrlen) == 0) {
        success = true;
      }
      close(fd);
    }
  }
  freeaddrinfo(result);
  *out = !success;
  return 0;
}

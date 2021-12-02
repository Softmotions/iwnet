#pragma once
#include "poller.h"

typedef int iwn_http_server_fd_t;

struct iwn_http_server {
  const char *listen;
  void       *user_data;
  iwn_http_server_fd_t fd;
  int port;
};

struct iwn_http_server_connection {
  const struct iwn_http_server *server;
  int fd;
};

typedef void (*iwn_http_server_on_dispose)(const struct iwn_http_server *server);

typedef void (*iwn_http_server_on_connection)(const struct iwn_http_server_connection *conn);

struct iwn_http_server_spec {
  const struct iwn_poller *poller;
  const char *listen;
  void       *user_data;
  iwn_http_server_on_connection on_connection;
  iwn_http_server_on_dispose    on_dispose;
  long connection_timeout_sec;
  int  port;
  bool https;
};

iwrc iwn_http_server_create(const struct iwn_http_server_spec *spec, iwn_http_server_fd_t *out_fd);

iwrc iwn_http_server_request_dispose(iwn_http_server_fd_t h);

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
  struct iwn_poller *poller;
  const char *listen;
  void       *user_data;
  iwn_http_server_on_connection on_connection;
  iwn_http_server_on_dispose    on_dispose;
  const char *certs_data;
  size_t      certs_data_len;
  const char *private_key;
  size_t      private_key_len;
  long http_max_total_mem_usage;
  int  port;
  int  request_timeout_sec;
  int  request_keepalive_timeout_sec;
  int  request_buf_size;
  int  response_buf_size;
  int  http_max_token_len;
  int  http_max_request_buf_size;
  bool certs_data_in_buffer;      ///< true if `certs_data` specified as data buffer rather a file name.
  bool private_key_in_buffer;     ///< true if `private_key_in_buffer` specified as data buffer rather a file name.
};

iwrc iwn_http_server_create(const struct iwn_http_server_spec *spec, iwn_http_server_fd_t *out_fd);

iwrc iwn_http_server_request_dispose(iwn_http_server_fd_t fd);

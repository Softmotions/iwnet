#pragma once
#include "poller.h"

struct iwn_http_chunk {
  const char *buf;
  int len;
};

struct iwn_http_server {
  const char *listen;
  void       *user_data;
  int fd;
  int port;
};

struct iwn_http_server_connection {
  const struct iwn_http_server *server;
  int fd;
};

struct iwn_http_header {
  const char *key;
  const char *value;
  struct iwn_http_header *next;
};

struct iwn_http_request {
  void *user_data; ///< User data specified in `iwn_http_server_spec`
  // TODO:
};

typedef void (*iwn_http_server_on_dispose)(const struct iwn_http_server*);

typedef void (*iwn_http_server_on_connection)(const struct iwn_http_server_connection*);

typedef void (*iwn_http_server_on_connection_close)(const struct iwn_http_server_connection*);

struct iwn_http_server_spec {
  /// Required request handler function.
  /// Returns `false` if client connection shold be removed from poller (terminated).
  bool (*request_handler) (struct iwn_http_request*);
  struct iwn_poller *poller; ///< Required poller reference.
  const char *listen;
  void       *user_data;
  iwn_http_server_on_connection       on_connection;
  iwn_http_server_on_connection_close on_connection_close;
  iwn_http_server_on_dispose on_server_dispose;
  const char *certs_data;
  size_t      certs_data_len;
  const char *private_key;
  size_t      private_key_len;
  long http_max_total_mem_usage;
  int  port;
  int  http_socket_queue_size;
  int  request_buf_max_size;
  int  request_buf_size;
  int  request_timeout_keepalive_sec;
  int  request_timeout_sec;
  int  request_token_max_len;
  int  request_max_header_count;
  int  response_buf_size;
  bool certs_data_in_buffer;      ///< true if `certs_data` specified as data buffer rather a file name.
  bool private_key_in_buffer;     ///< true if `private_key_in_buffer` specified as data buffer rather a file name.
};

iwrc iwn_http_server_create(const struct iwn_http_server_spec *spec, int *out_fd);

void iwn_http_stream_read_next(struct iwn_http_request *req, void (*chunk_cb) (struct iwn_http_request*, void*), void*);

bool iwn_http_is_streamed(struct iwn_http_request *req);

struct iwn_http_chunk iwn_http_stream_chunk(struct iwn_http_request *req);

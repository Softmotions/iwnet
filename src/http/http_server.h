#pragma once
#include "poller.h"

IW_EXTERN_C_START

struct iwn_http_val {
  const char *buf;
  size_t      len;
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

struct iwn_http_request {
  void *request_user_data; ///< Request specific user data.
  void *server_user_data;  ///< User data specified in `iwn_http_server_spec`
};

typedef void (*iwn_http_server_on_dispose)(const struct iwn_http_server*);

typedef void (*iwn_http_server_on_connection)(const struct iwn_http_server_connection*);

typedef void (*iwn_http_server_on_connection_close)(const struct iwn_http_server_connection*);

struct iwn_http_server_spec {
  /// Required request handler function.
  /// Returns `false` if client connection shold be removed from poller (terminated).
  bool (*request_handler)(struct iwn_http_request*);
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
  int  port;
  int  http_socket_queue_size;
  int  response_buf_size;
  int  request_buf_max_size;
  int  request_buf_size;
  int  request_timeout_keepalive_sec;
  int  request_timeout_sec;
  int  request_token_max_len;
  int  request_max_header_count;
  bool certs_data_in_buffer;      ///< true if `certs_data` specified as data buffer rather a file name.
  bool private_key_in_buffer;     ///< true if `private_key_in_buffer` specified as data buffer rather a file name.
};

IW_EXPORT WUR iwrc iwn_http_server_create(
  const struct iwn_http_server_spec*,
  int *out_fd);

IW_EXPORT void iwn_http_request_chunk_next(
  struct iwn_http_request*,
  void (*chunk_cb)(struct iwn_http_request*, void*),
  void*);

IW_EXPORT struct iwn_http_val iwn_http_request_chunk_get(struct iwn_http_request*);

IW_EXPORT bool iwn_http_request_is_streamed(struct iwn_http_request*);

IW_EXPORT void iwn_http_request_free(struct iwn_http_request*);

IW_EXPORT struct iwn_http_val iwn_http_request_target(struct iwn_http_request*);

IW_EXPORT bool iwn_http_request_target_is(struct iwn_http_request*, const char *target, ssize_t target_len);

IW_EXPORT struct iwn_http_val iwn_http_request_method(struct iwn_http_request*);

IW_EXPORT struct iwn_http_val iwn_http_request_body(struct iwn_http_request*);

IW_EXPORT struct iwn_http_val iwn_http_request_header_get(struct iwn_http_request*, const char *header_name);

IW_EXPORT bool iwn_http_request_headers_iterate(
  struct iwn_http_request*,
  struct iwn_http_val *key,
  struct iwn_http_val *val,
  int                 *iter);

IW_EXPORT void iwn_http_connection_set_automatic(struct iwn_http_request *request);

IW_EXPORT void iwn_http_connection_set_keep_alive(struct iwn_http_request*, bool keep_alive);

IW_EXPORT iwrc iwn_http_response_code_set(struct iwn_http_request*, int code);

IW_EXPORT int iwn_http_response_code_get(struct iwn_http_request*);

IW_EXPORT iwrc iwn_http_response_header_set(
  struct iwn_http_request*,
  const char *header_name,
  const char *header_value);

IW_EXPORT struct iwn_http_val iwn_http_response_header_get(struct iwn_http_request*, const char *header_name);

IW_EXPORT void iwn_http_response_body_clear(struct iwn_http_request*);

IW_EXPORT void iwn_http_response_body_set(
  struct iwn_http_request*,
  const char *body,
  ssize_t     body_len,
  void (     *body_free )(void*));

IW_EXPORT iwrc iwn_http_response_end(struct iwn_http_request*);

IW_EXPORT iwrc iwn_http_response_write_simple(
  struct iwn_http_request*,
  int         status_code,
  const char *content_type,
  char       *body,
  ssize_t     body_len,
  void (     *body_free )(void*));

IW_EXPORT iwrc iwn_http_response_chunk_write(
  struct iwn_http_request*,
  char *body,
  ssize_t body_len,
  void (*body_free)(void*),
  void (*chunk_cb)(struct iwn_http_request*, void*),
  void*);

IW_EXPORT iwrc iwn_http_response_chunk_end(struct iwn_http_request*);

IW_EXTERN_C_END

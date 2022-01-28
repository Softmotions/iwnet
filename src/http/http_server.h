#pragma once

#include "poller_adapter.h"
#include "utils/pairs.h"

#include <stdarg.h>

IW_EXTERN_C_START;

struct iwn_http_server {
  const char *listen;
  void       *user_data;
  int fd;
  int port;
};

struct iwn_http_req {
  void       *request_user_data;                         ///< Request specific user data.
  void       *server_user_data;                          ///< User data specified in `iwn_http_server_spec`
  const char *session_cookie_params;                     ///< Optional params used to store session cookie. Default: lax
  void (*on_request_dispose)(struct iwn_http_req*);      ///< Request dispose handler.
  void (*on_response_headers_write)(struct iwn_http_req*);
  bool (*on_response_completed)(struct iwn_http_req*);
  struct iwn_poller_adapter *poller_adapter;
};

typedef void (*iwn_http_server_on_dispose)(const struct iwn_http_server*);

/// Request handler.
/// Returns `false` if client connection shold be removed from poller (terminated).
typedef bool (*iwn_http_server_request_handler)(struct iwn_http_req*);
typedef iwn_http_server_request_handler iwn_http_server_request_chunk_handler;

struct iwn_http_server_spec {
  iwn_http_server_request_handler request_handler; ///< Required request handler.
  struct iwn_poller *poller;                       ///< Required poller reference.
  const char *listen;
  void       *user_data;
  iwn_http_server_on_dispose on_server_dispose;
  const char *certs;
  ssize_t     certs_len;
  const char *private_key;
  ssize_t     private_key_len;
  int  port;                          ///< Default: 8080 http, 8443 https
  int  socket_queue_size;             ///< Default: 64
  int  response_buf_size;             ///< Default: 1024
  int  request_buf_max_size;          ///< Default: 8Mb
  int  request_buf_size;              ///< Default: 1024
  int  request_timeout_keepalive_sec; ///< -1 Disable timeout, 0 Use default timeout: 120sec
  int  request_timeout_sec;           ///< -1 Disable timeout, 0 Use default timeout: 20sec
  int  request_token_max_len;         ///< Default: 8192
  int  request_max_headers_count;     ///< Default:  127
  bool certs_in_buffer;               ///< true if `certs_data` specified as data buffer rather a file name.
  bool private_key_in_buffer;         ///< true if `private_key_in_buffer` specified as data buffer rather a file name.
};

IW_EXPORT WUR iwrc iwn_http_server_create(
  const struct iwn_http_server_spec*,
  int *out_fd);

IW_EXPORT void iwn_http_request_chunk_next(struct iwn_http_req*, iwn_http_server_request_chunk_handler);

IW_EXPORT struct iwn_val iwn_http_request_chunk_get(struct iwn_http_req*);

IW_EXPORT bool iwn_http_request_is_streamed(struct iwn_http_req*);

IW_EXPORT void iwn_http_request_free(struct iwn_http_req*);

IW_EXPORT struct iwn_val iwn_http_request_target(struct iwn_http_req*);

IW_EXPORT bool iwn_http_request_target_is(struct iwn_http_req*, const char *target, ssize_t target_len);

IW_EXPORT struct iwn_val iwn_http_request_method(struct iwn_http_req*);

IW_EXPORT struct iwn_val iwn_http_request_body(struct iwn_http_req*);

IW_EXPORT struct iwn_val iwn_http_request_header_get(
  struct iwn_http_req*,
  const char *header_name,
  ssize_t     header_name_len);

IW_EXPORT bool iwn_http_request_headers_iterate(
  struct iwn_http_req*,
  struct iwn_val *key,
  struct iwn_val *val,
  int            *iter);

IW_EXPORT void iwn_http_connection_set_automatic(struct iwn_http_req *request);

IW_EXPORT void iwn_http_connection_set_keep_alive(struct iwn_http_req*, bool keep_alive);

IW_EXPORT void iwn_http_connection_set_upgrade(struct iwn_http_req*);

IW_EXPORT bool iwn_http_connection_is_upgrade(struct iwn_http_req*);

IW_EXPORT iwrc iwn_http_response_code_set(struct iwn_http_req*, int code);

IW_EXPORT int iwn_http_response_code_get(struct iwn_http_req*);

IW_EXPORT iwrc iwn_http_response_header_set(
  struct iwn_http_req*,
  const char *header_name,
  const char *header_value,
  ssize_t     header_value_len);

IW_EXPORT iwrc iwn_http_response_header_add(
  struct iwn_http_req*,
  const char *header_name,
  const char *header_value,
  ssize_t     header_value_len);

IW_EXPORT void iwn_http_response_header_exclude(struct iwn_http_req*, const char *header_name);

IW_EXPORT struct iwn_val iwn_http_response_header_get(struct iwn_http_req*, const char *header_name);

IW_EXPORT void iwn_http_response_body_clear(struct iwn_http_req*);

IW_EXPORT void iwn_http_response_body_set(
  struct iwn_http_req*,
  const char *body,
  ssize_t     body_len,
  void (     *body_free )(void*));

IW_EXPORT iwrc iwn_http_response_end(struct iwn_http_req*);

IW_EXPORT bool iwn_http_response_by_code(struct iwn_http_req*, int code);

IW_EXPORT bool iwn_http_response_write(
  struct iwn_http_req*,
  int         status_code,
  const char *content_type,
  const char *body,
  ssize_t     body_len,
  void (     *body_free )(void*));

IW_EXPORT bool iwn_http_response_printf(
  struct iwn_http_req*,
  int status_code, const char *content_type,
  const char *body_fmt, ...);

IW_EXPORT bool iwn_http_response_printf_va(
  struct iwn_http_req *req,
  int status_code, const char *content_type,
  const char *body_fmt, va_list va);

IW_EXPORT iwrc iwn_http_response_chunk_write(
  struct iwn_http_req*,
  char *body,
  ssize_t body_len,
  void (*body_free)(void*),
  iwn_http_server_request_chunk_handler);

IW_EXPORT iwrc iwn_http_response_chunk_end(struct iwn_http_req*);

IW_EXPORT void iwn_http_inject_poller_events_handler(struct iwn_http_req*, iwn_on_poller_adapter_event eh);

IW_EXTERN_C_END;

#pragma once

/// Low level HTTP server.

#include "iwn_poller_adapter.h"
#include "iwn_pairs.h"

#include <iowow/iwxstr.h>

#include <pthread.h>
#include <stdarg.h>

IW_EXTERN_C_START

struct iwn_http_server {
  const char *listen;
  void       *user_data;
  int fd;
  int port;
};

struct iwn_http_req {
  void   *user_data;                                ///< Arbitrary user defined data.
  int64_t user_id;                                  ///< Application controlled user id.
  pthread_mutex_t user_mtx;                         ///< Mutex associated with request, can be used by user code.
  uint64_t    user_flags;                           ///< Arbitrary user defined flags
  void       *server_user_data;                     ///< User data specified in `iwn_http_server_spec`
  const char *session_cookie_params;                ///< Optional params used to store session cookie. Default: lax
  void (*on_request_dispose)(struct iwn_http_req*); ///< Request dispose handler.
  void (*on_response_headers_write)(struct iwn_http_req*);
  bool (*on_response_completed)(struct iwn_http_req*);
  struct iwn_poller_adapter *poller_adapter;
  int session_cookie_max_age_sec; ///< Max age of session cookies sec.
};

typedef void (*iwn_http_server_on_dispose)(const struct iwn_http_server*);

/// Request handler.
/// Returns `false` if client connection shold be removed from poller (terminated).
///
typedef bool (*iwn_http_server_request_handler)(struct iwn_http_req*);
typedef bool (*iwn_http_server_chunk_handler)(struct iwn_http_req*, bool *again);

struct iwn_http_server_ssl_spec {
  const char *certs;
  const char *private_key;
  ssize_t     certs_len;
  ssize_t     private_key_len;
  bool private_key_in_buffer; ///< true if `certs_data` specified as data buffer rather a file name.
  bool certs_in_buffer;       ///< true if `private_key_in_buffer` specified as data buffer rather a file name.
};

struct iwn_http_server_spec {
  iwn_http_server_request_handler request_handler; ///< Required request handler.
  struct iwn_poller *poller;                       ///< Required poller reference.
  const char *listen;
  void       *user_data;
  iwn_http_server_on_dispose      on_server_dispose;
  struct iwn_http_server_ssl_spec ssl;
  int port;                           ///< Default: 8080 http, 8443 https
  int socket_queue_size;              ///< Default: 64
  int request_buf_max_size;           ///< Default: 8Mb
  int request_buf_size;               ///< Default: 1023, Min: 1023
  int request_timeout_keepalive_sec;  ///< -1 Disable timeout, 0 Use default timeout: 120sec
  int request_timeout_sec;            ///< -1 Disable timeout, 0 Use default timeout: 20sec
  int request_token_max_len;          ///< Default: 8191, Min: 8191
  int request_max_headers_count;      ///< Default:  127
};

/// Creates an instance of http server.
///
/// Registers server in the poller provider by struct iwn_http_server_spec.
///
/// @param[out] out_fd File descriptor of the server listener socket
///
IW_EXPORT WUR iwrc iwn_http_server_create(
  const struct iwn_http_server_spec*,
  int *out_fd);

/// Upgrade server accept routine configuration to use
/// SSL parameters provider by `ssl`.
///
/// @param poller Poller where server accept socket resides.
/// @param server_fd Server accept connection fd provided by iwn_http_server_create().
/// @param ssl SSL configuration.
///
IW_EXPORT bool iwn_http_server_ssl_set(
  struct iwn_poller                     *poller,
  int                                    server_fd,
  const struct iwn_http_server_ssl_spec *ssl);

/// Start reading the next chunk of data from request body.
IW_EXPORT void iwn_http_request_chunk_next(struct iwn_http_req*, iwn_http_server_chunk_handler);

/// Gets the current chunk of request data currently available.
/// Used by @ref iwn_http_server_chunk_handler
///
IW_EXPORT struct iwn_val iwn_http_request_chunk_get(struct iwn_http_req*);

/// Returns `true` when request in the streamed mode where `iwn_http_request_chunk_next()` calls in use.
/// Streamed mode is activated for chunked requests or when request body greater than 8Mb (defined by
/// @ref iwn_http_server_spec::request_buf_max_size)
///
IW_EXPORT bool iwn_http_request_is_streamed(struct iwn_http_req*);

/// Returns `true` when SSL(TLS) user i request transport connection.
IW_EXPORT bool iwn_http_request_is_secure(struct iwn_http_req*);

/// Returns remote ip address of request client.
IW_EXPORT const char* iwn_http_request_remote_ip(struct iwn_http_req*);

/// Get HTTP Target path for given request.
/// @note @ref iwn_val::buf "buf" value is not null terminated.
///
IW_EXPORT struct iwn_val iwn_http_request_target(struct iwn_http_req*);

/// Returns `true` if request target is matched to the given `target`
IW_EXPORT bool iwn_http_request_target_is(struct iwn_http_req*, const char *target, ssize_t target_len);

/// Get HTTP request method name.
/// @note @ref iwn_val::buf "buf" value is not null terminated.
///
IW_EXPORT struct iwn_val iwn_http_request_method(struct iwn_http_req*);

/// Get the body of HTTP request.
/// @warning This method works only when `iwn_http_request_is_streamed()` is false.
///
IW_EXPORT struct iwn_val iwn_http_request_body(struct iwn_http_req*);

/// Get the first occurrence of request heade`r value with given `header_name`.
/// If no header is found the zero `iwn_val` structure will be returned.
///
IW_EXPORT struct iwn_val iwn_http_request_header_get(
  struct iwn_http_req*,
  const char *header_name,
  ssize_t     header_name_len);

/// Create an iterator over request header values.
/// Returns `true` until iterator has next value.
///
/// @param[out] key Header name
/// @param[out] val Header value
/// @param[in,out] Iterator step. Must be zero on first run.
///
IW_EXPORT bool iwn_http_request_headers_iterate(
  struct iwn_http_req*,
  struct iwn_val *key,
  struct iwn_val *val,
  int            *iter);

/// Sets automatic keep-alive detection for request connection. Active by default.
IW_EXPORT void iwn_http_connection_set_automatic(struct iwn_http_req *request);

/// Force request connection to be in keep-alive mode.
IW_EXPORT void iwn_http_connection_set_keep_alive(struct iwn_http_req*, bool keep_alive);

/// Sets connection in `upgrade` mode. User by websocket server.
IW_EXPORT void iwn_http_connection_set_upgrade(struct iwn_http_req*);

/// Returns true if connection is in upgrade mode.
IW_EXPORT bool iwn_http_connection_is_upgrade(struct iwn_http_req*);

/// Sets HTTP response status code for given request object.
IW_EXPORT iwrc iwn_http_response_code_set(struct iwn_http_req*, int code);

/// Returns current HTTP status code set by `iwn_http_response_code_set()`
IW_EXPORT int iwn_http_response_code_get(struct iwn_http_req*);

/// Sets HTTP response header.
/// @note If header with the same `header_name` was set previously its value will be updated.
IW_EXPORT iwrc iwn_http_response_header_set(
  struct iwn_http_req*,
  const char *header_name,
  const char *header_value,
  ssize_t     header_value_len);

/// Sets HTTP response header with header value given as integer.
/// @note If header with the same `header_name` was set previously its value will be updated.
///
IW_EXPORT iwrc iwn_http_response_header_i64_set(
  struct iwn_http_req*,
  const char *header_name,
  int64_t     header_value);

/// Sets HTTP response header with printf formatted value.
/// @note If header with the same `header_name` was set previously its value will be updated.
///
IW_EXPORT iwrc iwn_http_response_header_printf_va(
  struct iwn_http_req *req,
  const char          *header_name,
  const char          *format,
  va_list              va);

/// Set HTTP response header with printf formatted value.
/// @note If header with the same `header_name` was set previously its value will be updated.
///
IW_EXPORT iwrc iwn_http_response_header_printf(
  struct iwn_http_req *req,
  const char          *header_name,
  const char          *format,
  ...) __attribute__((format(__printf__, 3, 4)));

/// Added HTTP response header.
IW_EXPORT iwrc iwn_http_response_header_add(
  struct iwn_http_req*,
  const char *header_name,
  const char *header_value,
  ssize_t     header_value_len);

/// Gets value of HTTP response header.
/// If no header is found the zero `iwn_val` structure will be returned.
///
IW_EXPORT struct iwn_val iwn_http_response_header_get(struct iwn_http_req*, const char *header_name);

/// Dispose response body.
IW_EXPORT void iwn_http_response_body_clear(struct iwn_http_req*);

/// Set response body.
/// @param body Body data buffer
/// @param body_len Body data length
/// @param body_free Optional body dispose callback.
///
IW_EXPORT void iwn_http_response_body_set(
  struct iwn_http_req*,
  const char *body,
  ssize_t     body_len,
  void (     *body_free )(void*));

/// Completes a response for given request.
/// All response headers, body will be transferred to the client peer.
///
IW_EXPORT iwrc iwn_http_response_end(struct iwn_http_req*);

/// Generate a minimal HTTP response according to the given HTTP response `code`.
IW_EXPORT bool iwn_http_response_by_code(struct iwn_http_req*, int code);

/// Writes a given response `body` and completes response for specified request.
IW_EXPORT bool iwn_http_response_write(
  struct iwn_http_req*,
  int         status_code,
  const char *content_type,
  const char *body,
  ssize_t     body_len);

/// Writes a given response as prinf formatted value and completes response for specified request.
IW_EXPORT bool iwn_http_response_printf(
  struct iwn_http_req*,
  int status_code, const char *content_type,
  const char *body_fmt, ...)
__attribute__((format(__printf__, 4, 5)));

/// Writes a given response as prinf formatted value and completes response for specified request.
IW_EXPORT bool iwn_http_response_printf_va(
  struct iwn_http_req*,
  int status_code, const char *content_type,
  const char *body_fmt, va_list va);

/// Starts/continues writing a chunked response.
/// `chunk_cb` used to fill the next chunk of data.
/// Set `again` to true if you want to repeat chunk writing iteration instead of recursive calling
/// `iwn_http_response_chunk_write()` for next chunk.
///
IW_EXPORT iwrc iwn_http_response_chunk_write(
  struct iwn_http_req*,
  char                         *body,
  ssize_t                       body_len,
  iwn_http_server_chunk_handler chunk_cb,
  bool                         *again);

/// Finishes a chunked response.
IW_EXPORT iwrc iwn_http_response_chunk_end(struct iwn_http_req*);

/// Starts writing of streamed response.
/// `chunk_cb` will be called later for fill next stream chunk.
IW_EXPORT iwrc iwn_http_response_stream_start(struct iwn_http_req*, iwn_http_server_chunk_handler chunk_cb);

/// Continues writing a streamed response.
/// `chunk_cb` used to fill the next chunk of data.
/// Set `again` to true if you want to repeat chunk writing iteration instead of recursive calling
/// `iwn_http_response_stream_write()` for next chunk.
///
IW_EXPORT void iwn_http_response_stream_write(
  struct iwn_http_req*,
  char                         *buf,
  ssize_t                       buf_len,
  void (                       *buf_free )(void*),
  iwn_http_server_chunk_handler chunk_cb,
  bool                         *again);

/// Finishes a streamed response.
IW_EXPORT void iwn_http_response_stream_end(struct iwn_http_req*);

IW_EXPORT void iwn_http_inject_poller_events_handler(struct iwn_http_req*, iwn_on_poller_adapter_event eh);

IW_EXTERN_C_END

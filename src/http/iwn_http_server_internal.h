#pragma once

#include "iwn_http_server.h"

/// Request transport operations.
///
/// A request served by HTTP/1 uses the implementation built into `iwn_http_server.c`
/// (`struct iwn_http_req::impl == 0`).
/// Alternative transports (HTTP/2) provide their own operations table.
struct iwn_http_req_ops {
  // Request
  struct iwn_val (*request_target)(struct iwn_http_req*);
  struct iwn_val (*request_method)(struct iwn_http_req*);
  struct iwn_val (*request_body)(struct iwn_http_req*);
  bool (*request_is_streamed)(struct iwn_http_req*);
  bool (*request_is_secure)(struct iwn_http_req*);
  bool (*request_is_http2)(struct iwn_http_req*);
  const char* (*request_remote_ip)(struct iwn_http_req*);
  struct iwn_val (*request_header_get)(struct iwn_http_req*, const char *header_name, ssize_t header_name_len);
  bool (*request_headers_iterate)(struct iwn_http_req*, struct iwn_val *key, struct iwn_val *val, int *iter);
  void (*request_chunk_next)(struct iwn_http_req*, iwn_http_server_chunk_handler);
  struct iwn_val (*request_chunk_get)(struct iwn_http_req*);
  void (*connection_set_automatic)(struct iwn_http_req*);
  void (*connection_set_keep_alive)(struct iwn_http_req*, bool keep_alive);
  void (*connection_set_upgrade)(struct iwn_http_req*);
  bool (*connection_is_upgrade)(struct iwn_http_req*);
  iwrc (*request_abort)(struct iwn_http_req*);

  // Response
  iwrc (*response_code_set)(struct iwn_http_req*, int code);
  int  (*response_code_get)(struct iwn_http_req*);
  iwrc (*response_header_add)(struct iwn_http_req*, const char *name, const char *value, ssize_t value_len);
  iwrc (*response_header_set)(struct iwn_http_req*, const char *name, const char *value, ssize_t value_len);
  struct iwn_val (*response_header_get)(struct iwn_http_req*, const char*name);
  void (*response_body_clear)(struct iwn_http_req*);
  void (*response_body_set)(struct iwn_http_req*, const char *body, ssize_t body_len, void (*body_free)(void*));
  iwrc (*response_end)(struct iwn_http_req*);
  iwrc (*response_transfer_buf)(struct iwn_http_req*, int status_code, const char *content_type, struct iwxstr *buf);
  iwrc (*response_chunk_write)(
    struct iwn_http_req*,
    char                         *body,
    ssize_t                       body_len,
    iwn_http_server_chunk_handler chunk_cb,
    bool                         *again);
  iwrc (*response_chunk_end)(struct iwn_http_req*);
  iwrc (*response_stream_start)(struct iwn_http_req*, iwn_http_server_chunk_handler chunk_cb);
  void (*response_stream_write)(
    struct iwn_http_req*, char *buf, ssize_t buf_len, void (*buf_free)(void*),
    iwn_http_server_chunk_handler chunk_cb, bool *again);
  void   (*response_stream_end)(struct iwn_http_req*);
  size_t (*response_pending)(struct iwn_http_req*);

  // Framework glue
  void (*wf_set)(
    struct iwn_http_req*, void *user_data,
    void (*wf_on_request_dispose)(struct iwn_http_req*),
    void (*wf_on_response_headers_write)(struct iwn_http_req*));
  void* (*wf_data)(struct iwn_http_req*);
  void  (*ws_set)(struct iwn_http_req*, void *user_data);
  void* (*ws_data)(struct iwn_http_req*);
  void  (*poller_events_inject)(struct iwn_http_req*, iwn_on_poller_adapter_event);
};

void iwn_http_request_wf_set(
  struct iwn_http_req*, void *user_data,
  void (*wf_on_request_dispose)(struct iwn_http_req*),
  void (*wf_on_response_headers_write)(struct iwn_http_req*));

void* iwn_http_request_wf_data(struct iwn_http_req*);

void iwn_http_request_ws_set(struct iwn_http_req*, void *user_data);

void* iwn_http_request_ws_data(struct iwn_http_req*);

///////////////////////////////////////////////////////////////////////////
// Connection level accessors used by alternative transports.
// All functions accept the HTTP/1 request object acting as connection anchor.
///////////////////////////////////////////////////////////////////////////

/// Returns server configuration of the connection serving given request.
struct iwn_http_server_spec* iwn_http_request_server_spec(struct iwn_http_req*);

/// Returns `true` if the underlying connection is a TLS connection.
bool iwn_http_request_conn_is_secure(struct iwn_http_req*);

/// Appends `date` header value for the server of given request to `out_buf`.
/// `out_buf` must be at least 32 bytes long.
void iwn_http_request_server_date(struct iwn_http_req*, char out_buf[32]);

/// Associates an alternative transport context with the connection.
/// `dispose` is called before the connection request object is destroyed.
void iwn_http_request_transport_set(struct iwn_http_req*, void *data, void (*dispose)(struct iwn_http_req*));

/// Returns alternative transport context associated with the connection.
void* iwn_http_request_transport_data(struct iwn_http_req*);

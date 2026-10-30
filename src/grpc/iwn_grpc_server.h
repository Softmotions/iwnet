#pragma once

/// gRPC Server Library

#include "iwn_grpc.h" // IWYU pragma: export
#include "iwn_pairs.h"
#include "iwn_poller_adapter.h"

IW_EXTERN_C_START;

struct iwn_grpc_server;
struct iwn_grpc_server_conn;
struct iwn_grpc_server_req;
struct iwn_grpc_server_msg;

/// Server level context passed into server callbacks.
struct iwn_grpc_server_ctx {
  iwrc rc;
  struct iwn_grpc_server *server;
  void *user_data;
};

/// Network connection level context passed into connection callbacks.
struct iwn_grpc_server_conn_ctx {
  iwrc rc;
  struct iwn_poller_adapter   *pa;
  struct iwn_grpc_server      *server;
  struct iwn_grpc_server_conn *conn;
  void *user_data;
};

/// Incoming gRPC request.
///
/// The request handle passed into callbacks is owned by the server and is valid
/// only while the request is alive. Call `iwn_grpc_server_req_ref()` if the
/// handle has to be used after the callback returns.
struct iwn_grpc_server_req {
  iwrc rc;                    ///< Request error code.
  struct iwn_grpc_server_conn_ctx conn_ctx;
  const char *path;           ///< `:path` pseudo header.
  const char *authority;      ///< `:authority` pseudo header.
  const char *method;         ///< `:method` pseudo header.
  const char *content_type;   ///< `content-type` header.
  const char *authorization;  ///< `authorization` header.
  const char *data_encoding;  ///< `grpc-encoding` of incoming messages, zero means `identity`.
  uint32_t    stream_id;      ///< HTTP/2 stream id.
  void       *user_data;      ///< Free for use by the request handler.
  void       *impl;
};

/// Incoming gRPC message.
struct iwn_grpc_server_msg {
  struct iwn_grpc_server_req *req;
  struct iwn_val msg;         ///< Serialized protobuf message data.
  bool compressed;            ///< Message payload is compressed according to `req->data_encoding`.
};

/// gRPC server configuration.
struct iwn_grpc_server_spec {
  /// Listen url. Required.
  /// Available url schemes:
  ///   grpc://<host>[:port]           TLS gRPC server.
  ///   grpc+plaintext://<host>[:port] Plain text gRPC server.
  ///   grpc+socket:///path/to/socket  gRPC server over UNIX socket file.
  ///
  const char *url;

  struct iwn_poller *poller;    ///< Poller instance. Required.
  void *user_data;              ///< User data for callbacks.
  long  inactivity_timeout_sec; ///< Connection data inactivity timeout in seconds.

  /// gRPC specific settings.
  struct {
    uint32_t    max_message_bytes;      ///< Max bytes of single gRPC message. Default: 1048576
    uint32_t    max_concurrent_streams; ///< Advertised max concurrent streams. Default: 256
    const char *accept_encoding;        ///< Comma separated compression encoding algos. Default: identity.
  } grpc;

  /// TLS server settings. Required for `grpc://` urls.
  struct {
    const char *certs;           ///< Certificate chain: PEM file path or PEM data.
    const char *private_key;     ///< Private key: PEM file path or PEM data.
    ssize_t     certs_len;       ///< Certificate data length. Negative value means strlen().
    ssize_t     private_key_len; ///< Private key data length. Negative value means strlen().
    bool certs_in_buffer;        ///< `certs` is PEM data rather than a file path.
    bool private_key_in_buffer;  ///< `private_key` is PEM data rather than a file path.
  } ssl;

  /// Server operation flags.
  /// @see IWN_GRPC_LOG_QUIET
  uint32_t flags;

  /// Called when request headers are received.
  /// Return zero to handle the request; a non zero error code causes the server
  /// to finish the request with the corresponding gRPC status.
  iwrc (*on_request)(struct iwn_grpc_server_req*);

  /// Called when a request message is received.
  /// Set `out_continue` to false to stop delivering further messages of this request.
  void (*on_message)(struct iwn_grpc_server_msg*, bool *out_continue);

  /// Called when the client side of the request stream is closed.
  void (*on_request_end)(struct iwn_grpc_server_req*);

  /// Called when the request stream is closed.
  void (*on_request_closed)(const struct iwn_grpc_server_req*);

  /// Called before destroying the request and its resources.
  void (*on_request_destroy)(const struct iwn_grpc_server_req*);

  /// Called when the network connection is closed.
  void (*on_closed)(struct iwn_grpc_server_conn_ctx*);

  /// Called when a generic HTTP2 session error occurred.
  void (*on_error)(struct iwn_grpc_server_conn_ctx*);

  /// Called before destroying the server and its resources.
  void (*on_destroy)(struct iwn_grpc_server_ctx*);

#ifdef IW_BLOCKS
  iwrc (^on_request_block)(struct iwn_grpc_server_req*);
  void (^on_message_block)(struct iwn_grpc_server_msg*, bool*);
  void (^on_request_end_block)(struct iwn_grpc_server_req*);
  void (^on_request_closed_block)(const struct iwn_grpc_server_req*);
  void (^on_request_destroy_block)(const struct iwn_grpc_server_req*);
  void (^on_closed_block)(struct iwn_grpc_server_conn_ctx*);
  void (^on_error_block)(struct iwn_grpc_server_conn_ctx*);
  void (^on_destroy_block)(struct iwn_grpc_server_ctx*);
#endif
};

/// Creates a gRPC server and starts listening on the configured url.
IW_EXPORT iwrc iwn_grpc_server_open(const struct iwn_grpc_server_spec*, struct iwn_grpc_server **out_server);

/// Initiates server shutdown and releases caller ownership of the server handle.
/// Returns false if the server was already closed.
IW_EXPORT bool iwn_grpc_server_close(struct iwn_grpc_server*);

/// Acquires an additional reference to the request handle.
IW_EXPORT struct iwn_grpc_server_req* iwn_grpc_server_req_ref(struct iwn_grpc_server_req*);

/// Releases a request reference previously acquired by `iwn_grpc_server_req_ref()`.
IW_EXPORT void iwn_grpc_server_req_unref(struct iwn_grpc_server_req*);

/// Writes response headers if not yet written.
/// `encoding` is the response compression encoding; zero means `identity`.
IW_EXPORT iwrc iwn_grpc_server_req_write_headers(struct iwn_grpc_server_req*, const char *encoding);

/// Queues a response message for sending.
/// Response headers are written automatically with `identity` encoding if needed.
/// `msg` is copied before this function returns.
IW_EXPORT iwrc iwn_grpc_server_req_write_message(
  struct iwn_grpc_server_req*,
  const struct iwn_val *msg,
  bool                  compressed);

/// Finishes the response once all queued messages are sent.
/// `rc` zero means `OK` gRPC status, otherwise the error is mapped to a gRPC status code.
/// `message` is an optional human readable error description.
IW_EXPORT iwrc iwn_grpc_server_req_end(struct iwn_grpc_server_req*, iwrc rc, const char *message);

/// Aborts the request stream with `RST_STREAM(CANCEL)`.
IW_EXPORT void iwn_grpc_server_req_cancel(struct iwn_grpc_server_req*);

IW_EXTERN_C_END;

#pragma once

/// gRPC Client Library

#include "iwn_grpc.h" // IWYU pragma: export
#include "iwn_poller_adapter.h"
#include  "utils/iwn_pairs.h"

IW_EXTERN_C_START;

struct iwn_grpc_client;
struct iwn_grpc_req_ctx;
struct iwn_grpc_req_spec;
struct iwn_grpc_req_message;

/// Context passed into client callback functions.
struct iwn_grpc_client_ctx {
  iwrc rc;
  struct iwn_poller_adapter *pa;
  struct iwn_grpc_client    *client;
  void *user_data;
};

struct iwn_grpc_req_spec {
  struct iwn_grpc_client *client; ///< gRPC Client connection. Required.
  const char *service;            ///< Service name. Required.
  const char *method;             ///< Service method. Required.
  bool  client_streaming;         ///<  Client streaming is allowed
  void *user_data;

  /// Called when HTTP2/gRPC errors recieved by response headers.
  void (*on_error)(const struct iwn_grpc_req_ctx*);

  /// Callback to get next message to be send to remote peer.
  /// void (*on_message_sent)(struct iwn_grpc_req_ctx*);

  /// When server message arrived to client.
  /// Set `out_continue` to true if reciever wants to close the current request.
  iwrc (*on_message)(const struct iwn_grpc_req_message*, bool *out_continue);

  /// Called when all outgoing messages sent to the reciever.
  void (*on_messages_sent)(const struct iwn_grpc_req_ctx *ctx);

  /// When opened stream is closed.
  void (*on_close)(const struct iwn_grpc_req_ctx*);

  /// Called on destroy client request and its resources.
  /// All handles to `struct iwn_grpc_req_ctx` will be invalid after call of this handle.
  void (*on_destroy)(const struct iwn_grpc_req_ctx*);
};

struct iwn_grpc_req_ctx {
  iwrc rc;
  struct iwn_grpc_client_ctx client_ctx;
  struct iwn_grpc_req_spec   req_spec;
  const char *error_explained;
  const char *data_encoding;
  uint32_t    req_id;                          ///< Aka stream-id.
  void       *impl;
};

struct iwn_grpc_req_message {
  struct iwn_grpc_req_ctx ctx;
  struct iwn_val msg;
  bool compressed;
};

/// gRPC client configuration.
struct iwn_grpc_client_spec {
  /// Connection url. Required.
  /// Available url schemes:
  ///   grpc://<host>[:port]  Standard secured gRPC connection.
  ///   grpc+plaintext://...  Non TLS plain text gRPC connection.
  ///   grpc+socket://...     gRPC connection over UNIX socket file.
  ///
  const char *url;
  const char *authority;
  const char *authorization;   ///< Optional authorization gRPC header.
  const char *user_agent;      ///< Override user-agent gRPC header. Default: "iwn-grpc-client/1"

  struct iwn_poller *poller;    ///< Poller instance. Required.
  void *user_data;              ///< User data for callbacks.
  long  inactivity_timeout_sec; ///< Connection data inactivity timeout in seconds.

  /// gRPC specific settings.
  struct {
    uint32_t    timeout_sec;       ///< grpc-timeout in seconds. Default: 30
    uint32_t    max_message_bytes; ///< Max bytes of signle gRPC message. Default: 1048576
    const char *accept_encoding;   ///< Comma separated compression encoding algos. Default: identity.
  } grpc;

  /// Client operation flags.
  /// @see GRPC_TLS_VERIFY_PEER
  /// @see GRPC_TLS_VERIFY_HOST
  /// @see GRPC_LOG_QUIET
  uint32_t flags;

  /// When network client connection opened.
  iwrc (*on_connected)(struct iwn_grpc_client_ctx*);

  /// When network client connection closed.
  void (*on_closed)(struct iwn_grpc_client_ctx*);

  /// When generic HTTP2 session error occuried.
  void (*on_error)(struct iwn_grpc_client_ctx*);

  /// Called before destroying client and its resources.
  /// All handles to client or requests will be invalid after call of this handle.
  void (*on_destroy)(struct iwn_grpc_client_ctx*);
};

IW_EXPORT iwrc iwn_grpc_client_open(const struct iwn_grpc_client_spec*, struct iwn_grpc_client **out_client);

IW_EXPORT bool iwn_grpc_client_close(struct iwn_grpc_client*);

IW_EXPORT iwrc iwn_grpc_client_request_open(const struct iwn_grpc_req_spec*, struct iwn_val *msg, uint32_t *out_req_id);

IW_EXPORT void iwn_grpc_client_request_close(struct iwn_grpc_req_ctx*);

IW_EXPORT struct iwn_grpc_req_ctx* iwn_grpc_client_acquire_request_ctx(
  struct iwn_grpc_client  *client,
  uint32_t                 req_id,
  struct iwn_grpc_req_ctx *out_ctx);

IW_EXPORT void iwn_grpc_client_release_request_ctx(struct iwn_grpc_req_ctx*);

IW_EXPORT iwrc iwn_grpc_client_stream_next_message(struct iwn_grpc_req_ctx*, struct iwn_val *msg, bool stop_streaming);

IW_EXTERN_C_END;

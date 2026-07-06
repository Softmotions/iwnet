#pragma once

/// gRPC Client Library

#include "iwn_grpc.h" // IWYU pragma: export
#include "iwn_poller_adapter.h"
#include  "utils/iwn_pairs.h"

IW_EXTERN_C_START;

struct iwn_grpc_client;

/// Protobuf Raw
typedef struct iwn_val iwn_protobuf_bin_t;

/// Context passed into client callback functions.
struct iwn_grpc_client_ctx {
  struct iwn_poller_adapter *pa;
  struct iwn_grpc_client    *grpc;
  void *user_data;
};

struct iwn_grpc_req_ctx {
  struct iwn_grpc_client_ctx *cctx;
  const char *path;   ///< Service path: <service name>/<method name>
  int32_t     req_id; ///< Aka stream-id.
};

/// Client control commands returned as result of some callbacks.
enum iwn_grpc_client_ctl {
  IWN_GRPC_CLIENT_CTL_STOP_SENDING = 0x01, ///< Stop sending client data to server.
  IWN_GRPC_CLIENT_CTL_CLOSE        = 0x02, ///< Close gRPC connection.
};

/// gRPC client configuration.
struct iwn_grpc_client_spec {
  /// Connection url. Required.
  const char *url;
  struct {
    uint32_t timeout_sec;  ///< grpc-timeout in seconds
  } grpc_defaults;
  struct {
    uint32_t max_frame_size; ///< SETTINGS_MAX_FRAME_SIZE
  } transport_settings;

  enum iwn_grpc_client_ctl (*on_connected)(struct iwn_grpc_client_ctx*);
  enum iwn_grpc_client_ctl (*on_message)(struct iwn_grpc_req_ctx*, iwn_protobuf_bin_t *msg);
  iwrc (*send_message)(struct iwn_grpc_client_ctx*, iwn_protobuf_bin_t *msg);
  void (*on_connection_close)(struct iwn_grpc_client_ctx*);
  void (*on_destroy)(struct iwn_grpc_client_ctx*);
};


IW_EXTERN_C_END;

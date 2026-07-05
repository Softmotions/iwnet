#pragma once

/// gRPC Client Library

#include "iwn_poller_adapter.h"
#include  "utils/iwn_pairs.h"

IW_EXTERN_C_START;

struct iwn_grpc_client;

/// Protobuf Raw
typedef struct iwn_val iwn_protobuf_bin;

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

/// gRPC client configuration.
struct iwn_grpc_client_spec {
  /// Connection url. Required.
  const char *url;
  uint32_t    grpc_default_timeout_sec; ///< grpc-timeout in seconds
};


IW_EXTERN_C_END;

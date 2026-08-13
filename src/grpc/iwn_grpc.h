#pragma once

#include <iowow/basedefs.h>

IW_EXTERN_C_START;

#define IWN_GRPC_TLS_VERIFY_PEER 0x01U ///< Verify peer on TLS connection.
#define IWN_GRPC_TLS_VERIFY_HOST 0x02U ///< Verify host on TLS connection.
#define IWN_GRPC_LOG_QUIET       0x04U ///< Let connections logging be less verbose

typedef enum {
  _GRPC_ERROR_START = (IW_ERROR_START + 206000UL),
  GRPC_ERROR,                     ///< Unknown/generic gRPC error.
  GRPC_ERROR_CONFIG,              ///< gRPC transport configuration error (GRPC_ERROR_CONFIG).
  GRPC_ERROR_PEER_CONNECT,        ///< Peer connection failed (WS_ERROR_PEER_CONNECT)
  GRPC_ERROR_CANCELLED,           ///< The operation was cancelled.
  GRPC_ERROR_INVALID_ARGUMENT,    ///< The client specified an invalid argument.
  GRPC_ERROR_DEADLINE_EXCEEDED,   ///< The deadline expired before the operation could complete.
  GRPC_ERROR_NOT_FOUND,           ///< Some requested entity was not found.
  GRPC_ERROR_ALREADY_EXISTS,      ///< The entity that a client attempted to create already exists.
  GRPC_ERROR_PERMISSION_DENIED,   ///< The caller does not have permission to execute the specified operation.
  GRPC_ERROR_RESOURCE_EXHAUSTED,  ///< Some resource has been exhausted.
  GRPC_ERROR_FAILED_PRECONDITION, ///< The operation was rejected because the system is not in a state required for the
                                  ///  operation’s execution.
  GRPC_ERROR_ABORTED,             ///< The operation was aborted.
  GRPC_ERROR_OUT_OF_RANGE,        ///< The operation was attempted past the valid range.
  GRPC_ERROR_UNIMPLEMENTED,       ///< The operation is not implemented or is not supported/enabled in this service.
  GRPC_ERROR_INTERNAL,            ///< Internal gRPC error.
  GRPC_ERROR_UNAVAILABLE,         ///< The service is currently unavailable. Try again later.
  GRPC_ERROR_DATA_LOSS,           ///< Unrecoverable data loss or corruption.
  GRPC_ERROR_UNAUTHENTICATED,     ///< The request does not have valid authentication credentials for the operation.

  GRPC_ERROR_STREAM_CLOSED,       ///< Stream closed. (GRPC_ERROR_STREAM_CLOSED)
  GRPC_ERROR_MSG_TOO_LARGE,       ///< gRPC message is too large (GRPC_ERROR_MSG_TOO_LARGE)

  GRPC_ERROR_H2,                   ///< HTTP2 Unknown/generic error. (GRPC_ERROR_H2)
  GRPC_ERROR_H2_UNEXPECTED_STATUS, ///< HTTP2  Unexpected HTTP status code. (GRPC_ERROR_H2_STATUS)
  GRPC_ERROR_H2_PROTOCOL,          ///< HTTP2 Protocol error. (GRPC_ERROR_H2_PROTOCOL)
  GRPC_ERROR_H2_COMPRESSION,       ///< HTTP2 Protocol compression error. (GRPC_ERROR_H2_COMPRESSION)
  GRPC_ERROR_H2_FLOW_CONTROL,      ///< HTTP2 Flow control error. (GRPC_ERROR_H2_FLOW_CONTROL)
  GRPC_ERROR_H2_REFUSED_STREAM,    ///< HTTP2 Refused stream. (GRPC_ERROR_H2_REFUSED_STREAM)
  GRPC_ERROR_H2_STREAM_CLOSED,     ///< HTTP2 Stream closed. (GRPC_ERROR_H2_STREAM_CLOSED)
  GRPC_ERROR_H2_GOAWAY,            ///< HTTP2 Go away (GRPC_ERROR_H2_GOAWAY)
  GRPC_ERROR_H2_CANCEL,            ///< HTTP2 Cancel (GRPC_ERROR_H2_CANCEL)

  _GRPC_ERROR_END,
} iwn_grpc_ecode_e;

IW_EXTERN_C_END;

iwrc iwn_grpc_init(void);

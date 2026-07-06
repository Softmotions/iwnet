#pragma once

#include <iowow/basedefs.h>

IW_EXTERN_C_START;

typedef enum {
  _GRPC_ERROR_START = (IW_ERROR_START + 206000UL),
  GRPC_ERROR,                     ///< Unknown/generic gRPC error.
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
  _GRPC_ERROR_END,
} iwn_grpc_ecode_e;

IW_EXTERN_C_END;

iwrc iwn_grpc_init(void);

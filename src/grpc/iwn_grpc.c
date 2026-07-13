#include "iwn_grpc.h"
#include <iowow/iwlog.h>
#include <stdlib.h>

static const char* _ecodefn(locale_t locale, uint32_t ecode) {
  if (ecode <= _GRPC_ERROR_START || ecode >= _GRPC_ERROR_END) {
    return 0;
  }
  switch (ecode) {
    case GRPC_ERROR:
      return "Unknown/generic gRPC error. (GRPC_ERROR)";
    case GRPC_ERROR_CONFIG:
      return "gRPC transport configuration error. (GRPC_ERROR_CONFIG)";
    case GRPC_ERROR_PEER_CONNECT:
      return "Peer connection failed. (GRPC_ERROR_PEER_CONNECT)";
    case GRPC_ERROR_CANCELLED:
      return "The operation was cancelled. (GRPC_ERROR_CANCELLED)";
    case GRPC_ERROR_INVALID_ARGUMENT:
      return "The client specified an invalid argument. (GRPC_ERROR_INVALID_ARGUMENT)";
    case GRPC_ERROR_DEADLINE_EXCEEDED:
      return "The deadline expired before the operation could complete. (GRPC_ERROR_DEADLINE_EXCEEDED)";
    case GRPC_ERROR_NOT_FOUND:
      return "Some requested entity was not found. (GRPC_ERROR_NOT_FOUND)";
    case GRPC_ERROR_ALREADY_EXISTS:
      return "The entity that a client attempted to create already exists. (GRPC_ERROR_ALREADY_EXISTS)";
    case GRPC_ERROR_PERMISSION_DENIED:
      return "The caller does not have permission to execute the specified operation. (GRPC_ERROR_PERMISSION_DENIED)";
    case GRPC_ERROR_RESOURCE_EXHAUSTED:
      return "Some resource has been exhausted. (GRPC_ERROR_RESOURCE_EXHAUSTED)";
    case GRPC_ERROR_FAILED_PRECONDITION:
      return
        "The operation was rejected because the system is not in a state required for operation's execution. (GRPC_ERROR_FAILED_PRECONDITION)";
    case GRPC_ERROR_ABORTED:
      return "The operation was aborted. (GRPC_ERROR_ABORTED)";
    case GRPC_ERROR_OUT_OF_RANGE:
      return "The operation was attempted past the valid range. (GRPC_ERROR_OUT_OF_RANGE)";
    case GRPC_ERROR_UNIMPLEMENTED:
      return "The operation is not implemented or is not supported/enabled in this service. (GRPC_ERROR_UNIMPLEMENTED)";
    case GRPC_ERROR_INTERNAL:
      return "Internal gRPC error. (GRPC_ERROR_INTERNAL)";
    case GRPC_ERROR_UNAVAILABLE:
      return "The service is currently unavailable. Try again later. (GRPC_ERROR_UNAVAILABLE)";
    case GRPC_ERROR_DATA_LOSS:
      return "Unrecoverable data loss or corruption. (GRPC_ERROR_DATA_LOSS)";
    case GRPC_ERROR_UNAUTHENTICATED:
      return
        "The request does not have valid authentication credentials for the operation. (GRPC_ERROR_UNAUTHENTICATED)";
    case GRPC_ERROR_H2:
      return "HTTP2 Unknown/generic error. (GRPC_ERROR_H2)";
    case GRPC_ERROR_H2_PROTOCOL:
      return "HTTP2 Protocol error. (GRPC_ERROR_H2_PROTOCOL)";
    case GRPC_ERROR_H2_COMPRESSION:
      return "HTTP2 Protocol comression error. (GRPC_ERROR_H2_COMPRESSION)";
    case GRPC_ERROR_H2_FLOW_CONTROL:
      return "HTTP2 Flow control error. (GRPC_ERROR_H2_FLOW_CONTROL)";
    case GRPC_ERROR_H2_REFUSED_STREAM:
      return "HTTP2 Refused stream. (GRPC_ERROR_H2_REFUSED_STREAM)";
    case GRPC_ERROR_H2_STREAM_CLOSED:
      return "HTTP2 Stream closed. (GRPC_ERROR_H2_STREAM_CLOSED)";
    case GRPC_ERROR_H2_GOAWAY:
      return "HTTP2 Go away. (GRPC_ERROR_H2_GOAWAY)";
    case GRPC_ERROR_H2_CANCEL:
      return "HTTP2 Cancel. (GRPC_ERROR_H2_CANCEL)";
  }
  return 0;
}

iwrc iwn_grpc_init(void) {
  static bool _initialized;
  if (__sync_bool_compare_and_swap(&_initialized, false, true)) {
    RCR(iwlog_register_ecodefn(_ecodefn));
  }
  return 0;
}

IW_CONSTRUCTOR void _init(void) {
  if (iwn_grpc_init()) {
    fputs("iwn_grpc_init() failed", stderr);
    abort();
  }
}

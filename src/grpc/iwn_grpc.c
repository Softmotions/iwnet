#include "iwn_grpc.h"
#include <iowow/iwlog.h>
#include <stdlib.h>

static const char* _ecodefn(locale_t locale, uint32_t ecode) {
  if (ecode <= _GRPC_ERROR_START || ecode >= _GRPC_ERROR_END) {
    return 0;
  }
  switch (ecode) {
    case GRPC_ERROR:
      return "Unknown/generic gRPC error.";
    case GRPC_ERROR_CANCELLED:
      return "The operation was cancelled.";
    case GRPC_ERROR_INVALID_ARGUMENT:
      return "The client specified an invalid argument.";
    case GRPC_ERROR_DEADLINE_EXCEEDED:
      return "The deadline expired before the operation could complete.";
    case GRPC_ERROR_NOT_FOUND:
      return "Some requested entity was not found.";
    case GRPC_ERROR_ALREADY_EXISTS:
      return "The entity that a client attempted to create already exists.";
    case GRPC_ERROR_PERMISSION_DENIED:
      return "The caller does not have permission to execute the specified operation.";
    case GRPC_ERROR_RESOURCE_EXHAUSTED:
      return "Some resource has been exhausted.";
    case GRPC_ERROR_FAILED_PRECONDITION:
      return "The operation was rejected because the system is not in a state required for operation's execution.";
    case GRPC_ERROR_ABORTED:
      return "The operation was aborted.";
    case GRPC_ERROR_OUT_OF_RANGE:
      return "The operation was attempted past the valid range.";
    case GRPC_ERROR_UNIMPLEMENTED:
      return "The operation is not implemented or is not supported/enabled in this service.";
    case GRPC_ERROR_INTERNAL:
      return "Internal gRPC error.";
    case GRPC_ERROR_UNAVAILABLE:
      return "The service is currently unavailable. Try again later.";
    case GRPC_ERROR_DATA_LOSS:
      return "Unrecoverable data loss or corruption.";
    case GRPC_ERROR_UNAUTHENTICATED:
      return "The request does not have valid authentication credentials for the operation.";
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

#pragma once

/// Selection of the TLS implementation used by iwnet network transports.
///
/// @see iwn_tls_poller_adapter.h

#include <iowow/basedefs.h>

IW_EXTERN_C_START;

/// TLS implementation.
typedef enum {
  /// BearSSL TLS 1.2 implementation. Default value.
  IWN_TLS_IMPL_BEARSSL = 0,
  /// AWS s2n-tls implementation.
  /// Available only if the library is built with `IWN_ENABLE_S2N`.
  IWN_TLS_IMPL_S2N = 1,
} iwn_tls_impl_e;

typedef enum {
  _IWN_TLS_ERROR_START = (IW_ERROR_START + 207000UL),
  IWN_TLS_ERROR_NOT_AVAILABLE, ///< Requested TLS implementation is not available (IWN_TLS_ERROR_NOT_AVAILABLE)
  IWN_TLS_ERROR_CERT_DATA,     ///< Invalid certificate data (IWN_TLS_ERROR_CERT_DATA)
  IWN_TLS_ERROR_PRIVKEY_DATA,  ///< Invalid private key data (IWN_TLS_ERROR_PRIVKEY_DATA)
  IWN_TLS_ERROR_HANDSHAKE,     ///< TLS handshake failed (IWN_TLS_ERROR_HANDSHAKE)
  _IWN_TLS_ERROR_END,
} iwn_tls_ecode_e;

/// Returns `true` if the given TLS implementation is available in this build.
IW_EXPORT bool iwn_tls_impl_available(iwn_tls_impl_e impl);

/// Returns the name of the TLS implementation or `"unknown"` for an unknown value.
IW_EXPORT const char* iwn_tls_impl_name(iwn_tls_impl_e impl);

IW_EXTERN_C_END;

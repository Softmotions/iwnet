#pragma once

/// TLS poller adapter which dispatches to the TLS implementation
/// selected by `tls_impl`.
///
/// @see iwn_brssl_poller_adapter.h
/// @see iwn_s2n_poller_adapter.c

#include "iwn_poller_adapter.h"
#include "iwn_tls.h"

IW_EXTERN_C_START;

struct iwn_tls_client_poller_adapter_spec {
  iwn_tls_impl_e     tls_impl;          ///< TLS implementation. Default: `IWN_TLS_IMPL_BEARSSL`
  struct iwn_poller *poller;
  const char *host;                     ///< Peer host name used for SNI and host verification.
  iwn_on_poller_adapter_event   on_event;
  iwn_on_poller_adapter_dispose on_dispose;
  const char *alpn_protocol_names;      ///< Comma separated list of protocol names.
  const char *cacerts_data;             ///< Optional CA certificates PEM data buffer.
  size_t      cacerts_data_len;         ///< Length of `cacerts_data` buffer.
  void       *user_data;
  long     timeout_sec;
  uint32_t events;
  uint32_t events_mod;
  int      fd;
  bool     verify_peer;
  bool     verify_host;
};

/// Creates a TLS client poller adapter using the selected implementation.
IW_EXPORT iwrc iwn_tls_client_poller_adapter(const struct iwn_tls_client_poller_adapter_spec *spec);

struct iwn_tls_server_poller_adapter_spec {
  iwn_tls_impl_e     tls_impl;          ///< TLS implementation. Default: `IWN_TLS_IMPL_BEARSSL`
  struct iwn_poller *poller;
  iwn_on_poller_adapter_event   on_event;
  iwn_on_poller_adapter_dispose on_dispose;
  const char *alpn_protocol_names;      ///< Comma separated list of protocol names.
  const char *certs;                    ///< PEM certificate chain: file path or PEM data.
  const char *private_key;              ///< PEM private key: file path or PEM data.
  ssize_t     certs_len;                ///< Certificate data length. Negative value means strlen().
  ssize_t     private_key_len;          ///< Private key data length. Negative value means strlen().
  void       *user_data;
  long     timeout_sec;
  uint32_t events;
  uint32_t events_mod;
  int      fd;
  bool     certs_in_buffer;             ///< `certs` is PEM data rather than a file path.
  bool     private_key_in_buffer;       ///< `private_key` is PEM data rather than a file path.
};

/// Creates a TLS server poller adapter using the selected implementation.
IW_EXPORT iwrc iwn_tls_server_poller_adapter(const struct iwn_tls_server_poller_adapter_spec *spec);

IW_EXTERN_C_END;

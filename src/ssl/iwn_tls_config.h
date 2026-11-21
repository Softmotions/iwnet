#pragma once

/// TLS settings shared by the connections of a server instance or a client.
///
/// Settings are immutable after creation and certificate material is parsed once,
/// so connections borrowing them do not pay the parsing cost. Typical owners are
/// the HTTP/gRPC servers and the ws/gRPC clients, which keep the settings for their
/// whole lifetime and reuse them for reconnects.
///
/// Ownership is borrow-only: there is no reference counting. The config owner keeps
/// it alive until the last adapter borrowing it is disposed and then calls the
/// matching `_free()` function.
///
/// @see iwn_tls_poller_adapter.h

#include "iwn_tls.h"
#include "iwn_tls_poller_adapter.h"

IW_EXTERN_C_START;

///////////////////////////////////////////////////////////////////////////
//                               Server                                  //
///////////////////////////////////////////////////////////////////////////

struct iwn_tls_server_config;

struct iwn_tls_server_config_spec {
  iwn_tls_impl_e tls_impl;            ///< TLS implementation. Default: `IWN_TLS_IMPL_BEARSSL`
  const char    *alpn_protocol_names; ///< Comma separated list of protocol names.
  const char    *certs;               ///< PEM certificate chain: file path or PEM data.
  const char    *private_key;         ///< PEM private key: file path or PEM data.
  ssize_t certs_len;                  ///< Certificate data length. Negative value means strlen().
  ssize_t private_key_len;            ///< Private key data length. Negative value means strlen().
  bool    certs_in_buffer;            ///< `certs` is PEM data rather than a file path.
  bool    private_key_in_buffer;      ///< `private_key` is PEM data rather than a file path.
};

/// Creates immutable server TLS settings.
///
/// Certificate chain, private key and ALPN protocol names are loaded and parsed
/// once, here.
iwrc iwn_tls_server_config_new(
  const struct iwn_tls_server_config_spec *spec,
  struct iwn_tls_server_config           **out_config);

/// Frees the server settings.
///
/// All adapters borrowing this config must be disposed before this call.
void iwn_tls_server_config_free(struct iwn_tls_server_config *config);

/// Creates a TLS server poller adapter which borrows `config`.
///
/// `config` must outlive the adapter. Only the `poller`, `on_event`,
/// `on_dispose`, `user_data`, `timeout_sec`, `events`, `events_mod` and `fd`
/// fields of `spec` are used: certificates, private key and ALPN protocols are
/// taken from `config`.
iwrc iwn_tls_server_poller_adapter_borrow(
  const struct iwn_tls_server_poller_adapter_spec *spec,
  const struct iwn_tls_server_config              *config);

///////////////////////////////////////////////////////////////////////////
//                               Client                                  //
///////////////////////////////////////////////////////////////////////////

struct iwn_tls_client_config;

struct iwn_tls_client_config_spec {
  iwn_tls_impl_e tls_impl;            ///< TLS implementation. Default: `IWN_TLS_IMPL_BEARSSL`
  const char    *alpn_protocol_names; ///< Comma separated list of protocol names.
  const char    *cacerts_data;        ///< CA certificates PEM data. Default: `iwn_cacerts`
  size_t cacerts_data_len;            ///< Length of `cacerts_data`.
  bool   verify_peer;                 ///< Verify the peer certificate chain.
  bool   verify_host;                 ///< Verify the peer host name.
};

/// Creates immutable client TLS settings.
///
/// Trust anchors and ALPN protocol names are loaded once, here.
iwrc iwn_tls_client_config_new(
  const struct iwn_tls_client_config_spec *spec,
  struct iwn_tls_client_config           **out_config);

/// Frees the client settings.
///
/// All adapters borrowing this config must be disposed before this call.
void iwn_tls_client_config_free(struct iwn_tls_client_config *config);

/// Creates a TLS client poller adapter which borrows `config`.
///
/// `config` must outlive the adapter. The peer verification mode is a part of the
/// settings, so `spec->verify_peer` and `spec->verify_host` must match the ones used
/// to create `config`. Only the `poller`, `host`, `on_event`, `on_dispose`,
/// `user_data`, `timeout_sec`, `events`, `events_mod` and `fd` fields of `spec` are
/// used, everything else is taken from `config`.
iwrc iwn_tls_client_poller_adapter_borrow(
  const struct iwn_tls_client_poller_adapter_spec *spec,
  const struct iwn_tls_client_config              *config);

///////////////////////////////////////////////////////////////////////////
//                       Implementation specific                         //
///////////////////////////////////////////////////////////////////////////

#ifdef IWN_ENABLE_S2N

struct iwn_s2n_server_config;

iwrc iwn_s2n_server_config_new(
  const struct iwn_tls_server_config_spec *spec,
  struct iwn_s2n_server_config           **out_config);

void iwn_s2n_server_config_free(struct iwn_s2n_server_config *config);

iwrc iwn_s2n_server_poller_adapter_borrow(
  const struct iwn_tls_server_poller_adapter_spec *spec,
  const struct iwn_s2n_server_config              *config);

struct iwn_s2n_client_config;

iwrc iwn_s2n_client_config_new(
  const struct iwn_tls_client_config_spec *spec,
  struct iwn_s2n_client_config           **out_config);

void iwn_s2n_client_config_free(struct iwn_s2n_client_config *config);

iwrc iwn_s2n_client_poller_adapter_borrow(
  const struct iwn_tls_client_poller_adapter_spec *spec,
  const struct iwn_s2n_client_config              *config);

#endif

struct iwn_brssl_server_config;

iwrc iwn_brssl_server_config_new(
  const struct iwn_tls_server_config_spec *spec,
  struct iwn_brssl_server_config         **out_config);

void iwn_brssl_server_config_free(struct iwn_brssl_server_config *config);

iwrc iwn_brssl_server_poller_adapter_borrow(
  const struct iwn_tls_server_poller_adapter_spec *spec,
  const struct iwn_brssl_server_config            *config);

struct iwn_brssl_client_config;

iwrc iwn_brssl_client_config_new(
  const struct iwn_tls_client_config_spec *spec,
  struct iwn_brssl_client_config         **out_config);

void iwn_brssl_client_config_free(struct iwn_brssl_client_config *config);

iwrc iwn_brssl_client_poller_adapter_borrow(
  const struct iwn_tls_client_poller_adapter_spec *spec,
  const struct iwn_brssl_client_config            *config);

IW_EXTERN_C_END;

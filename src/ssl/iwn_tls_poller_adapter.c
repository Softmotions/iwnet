#include "iwnet.h"
#include "iwn_tls_poller_adapter.h"
#include "iwn_brssl_poller_adapter.h"
#ifdef IWN_ENABLE_S2N
#include "iwn_s2n_poller_adapter.h"
#endif

#include <iowow/iwlog.h>

static const char* _ecodefn(locale_t locale, uint32_t ecode) {
  if (ecode <= _IWN_TLS_ERROR_START || ecode >= _IWN_TLS_ERROR_END) {
    return 0;
  }
  switch (ecode) {
    case IWN_TLS_ERROR_NOT_AVAILABLE:
      return "TLS implementation is not available (IWN_TLS_ERROR_NOT_AVAILABLE)";
    case IWN_TLS_ERROR_CERT_DATA:
      return "Invalid TLS certificate data (IWN_TLS_ERROR_CERT_DATA)";
    case IWN_TLS_ERROR_PRIVKEY_DATA:
      return "Invalid TLS private key data (IWN_TLS_ERROR_PRIVKEY_DATA)";
    case IWN_TLS_ERROR_HANDSHAKE:
      return "TLS handshake failed (IWN_TLS_ERROR_HANDSHAKE)";
  }
  return 0;
}

static void _init(void) {
  static bool _initialized = false;
  if (__sync_bool_compare_and_swap(&_initialized, false, true)) {
    iwlog_register_ecodefn(_ecodefn);
  }
}

bool iwn_tls_impl_available(iwn_tls_impl_e impl) {
  _init();
  switch (impl) {
    case IWN_TLS_IMPL_BEARSSL:
      return true;
    case IWN_TLS_IMPL_S2N:
#ifdef IWN_ENABLE_S2N
      return true;
#else
      return false;
#endif
  }
  return false;
}

const char* iwn_tls_impl_name(iwn_tls_impl_e impl) {
  switch (impl) {
    case IWN_TLS_IMPL_BEARSSL:
      return "bearssl";
    case IWN_TLS_IMPL_S2N:
      return "s2n";
  }
  return "unknown";
}

iwrc iwn_tls_client_poller_adapter(const struct iwn_tls_client_poller_adapter_spec *spec) {
  if (!spec) {
    return IW_ERROR_INVALID_ARGS;
  }
  _init();
  switch (spec->tls_impl) {
    case IWN_TLS_IMPL_BEARSSL:
      return iwn_brssl_client_poller_adapter(&(struct iwn_brssl_client_poller_adapter_spec) {
      .poller = spec->poller,
      .host = spec->host,
      .on_event = spec->on_event,
      .on_dispose = spec->on_dispose,
      .alpn_protocol_names = spec->alpn_protocol_names,
      .cacerts_data = spec->cacerts_data,
      .cacerts_data_len = spec->cacerts_data_len,
      .user_data = spec->user_data,
      .timeout_sec = spec->timeout_sec,
      .events = spec->events,
      .events_mod = spec->events_mod,
      .fd = spec->fd,
      .verify_peer = spec->verify_peer,
      .verify_host = spec->verify_host,
    });
    case IWN_TLS_IMPL_S2N:
#ifdef IWN_ENABLE_S2N
      return iwn_s2n_client_poller_adapter(spec);
#else
      break;
#endif
  }
  iwlog_ecode_error(IWN_TLS_ERROR_NOT_AVAILABLE,
                    "TLS implementation '%s' is not available", iwn_tls_impl_name(spec->tls_impl));
  return IWN_TLS_ERROR_NOT_AVAILABLE;
}

iwrc iwn_tls_server_poller_adapter(const struct iwn_tls_server_poller_adapter_spec *spec) {
  if (!spec) {
    return IW_ERROR_INVALID_ARGS;
  }
  _init();
  switch (spec->tls_impl) {
    case IWN_TLS_IMPL_BEARSSL:
      return iwn_brssl_server_poller_adapter(&(struct iwn_brssl_server_poller_adapter_spec) {
      .poller = spec->poller,
      .on_event = spec->on_event,
      .on_dispose = spec->on_dispose,
      .alpn_protocol_names = spec->alpn_protocol_names,
      .certs = spec->certs,
      .private_key = spec->private_key,
      .certs_len = spec->certs_len,
      .private_key_len = spec->private_key_len,
      .user_data = spec->user_data,
      .timeout_sec = spec->timeout_sec,
      .events = spec->events,
      .events_mod = spec->events_mod,
      .fd = spec->fd,
      .certs_in_buffer = spec->certs_in_buffer,
      .private_key_in_buffer = spec->private_key_in_buffer,
    });
    case IWN_TLS_IMPL_S2N:
#ifdef IWN_ENABLE_S2N
      return iwn_s2n_server_poller_adapter(spec);
#else
      break;
#endif
  }
  iwlog_ecode_error(IWN_TLS_ERROR_NOT_AVAILABLE,
                    "TLS implementation '%s' is not available", iwn_tls_impl_name(spec->tls_impl));
  return IWN_TLS_ERROR_NOT_AVAILABLE;
}

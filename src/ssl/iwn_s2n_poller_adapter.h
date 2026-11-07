#pragma once

/// s2n-tls poller adapter.
///
/// Internal API, use `iwn_tls_*_poller_adapter()` to create TLS poller adapters.
///
/// @see iwn_tls_poller_adapter.h

#include "iwn_tls_poller_adapter.h"

IW_EXTERN_C_START;

IW_EXPORT iwrc iwn_s2n_client_poller_adapter(const struct iwn_tls_client_poller_adapter_spec *spec);

IW_EXPORT iwrc iwn_s2n_server_poller_adapter(const struct iwn_tls_server_poller_adapter_spec *spec);

IW_EXTERN_C_END;

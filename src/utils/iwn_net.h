#pragma once

#include "iwnet.h"

IW_EXTERN_C_START;

/// Checks if given network `port` is bound on specified `listen` address.
///
/// Accourding to protocol and address types `flags` defined in iwnet.h
/// - IWN_IPV4
/// - IWN_IPV6
/// - IWN_TCP
/// - IWN_UDP
///
IW_EXPORT iwrc iwn_port_is_bound(const char *listen, int port, uint32_t flags, bool *out);

IW_EXTERN_C_END;

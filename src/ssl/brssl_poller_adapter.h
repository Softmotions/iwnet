#pragma once

#include "poller_adapter.h"

typedef enum {
  _BRS_ERROR_START = (IW_ERROR_START + 204000UL),
  BRS_ERROR_INVALID_CASCERT_DATA, ///< Invalid CA cetificates (BRS_ERROR_INVALID_CASCERT_DATA)
  _BRS_ERROR_END,
} brssl_poller_adapter_e;


struct brssl_poller_adapter_spec {
  struct poller *poller;
  const char    *host;
  on_poller_adapter_event   on_event;
  on_poller_adapter_dispose on_dispose;
  void    *user_data;
  long     timeout_sec;
  uint32_t events;
  uint32_t events_mod;
  int      fd;
  bool     verify_peer;
  bool     verify_host;
};

iwrc brssl_create_poller_adapter(const struct brssl_poller_adapter_spec *spec);

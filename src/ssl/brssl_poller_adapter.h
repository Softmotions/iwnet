#pragma once

#include "poller_adapter.h"

typedef enum {
  _BRS_ERROR_START = (IW_ERROR_START + 204000UL),
  BRS_ERROR_INVALID_CASCERT_DATA, ///< Invalid CA cetificates (BRS_ERROR_INVALID_CASCERT_DATA)
  BRS_ERROR_INVALID_PRIVKEY_DATA, ///< Invalid private key data (BRS_ERROR_INVALID_PRIVKEY_DATA)
  _BRS_ERROR_END,
} iwn_brssl_poller_adapter_e;


struct iwn_brssl_client_poller_adapter_spec {
  struct iwn_poller *poller;
  const char *host;
  iwn_on_poller_adapter_event   on_event;
  iwn_on_poller_adapter_dispose on_dispose;
  const char *cacerts_data;     ///< Optional cacerts pem data buffer.
  size_t      cacerts_data_len; ///< Length of caceprt pem buffer.
  void       *user_data;
  long     timeout_sec;
  uint32_t events;
  uint32_t events_mod;
  int      fd;
  bool     verify_peer;
  bool     verify_host;
};

iwrc iwn_brssl_client_poller_adapter(const struct iwn_brssl_client_poller_adapter_spec *spec);

struct iwn_brssl_server_poller_adapter_spec {
  struct iwn_poller *poller;
  iwn_on_poller_adapter_event   on_event;
  iwn_on_poller_adapter_dispose on_dispose;
  const char *certs_data;
  const char *private_key;
  size_t      certs_data_len;
  size_t      private_key_len;
  void       *user_data;
  long     timeout_sec;
  uint32_t events;
  uint32_t events_mod;
  int      fd;
  bool     certs_data_in_buffer;  ///< true if `certs_data` specified as data buffer rather a file name.
  bool     private_key_in_buffer; ///< true if `private_key_in_buffer` specified as data buffer rather a file name.
};

iwrc iwn_brssl_server_poller_adapter(const struct iwn_brssl_server_poller_adapter_spec *spec);

#include "http_server.h"
#include "poller_adapter.h"

iwrc iwn_http_server_create(
  struct iwn_poller *p, int port, const char *listen, bool http,
  iwn_http_server_handle_t *out_handle) {

  return 0;
}

iwrc iwn_http_server_dispose(iwn_http_server_handle_t h) {
  return 0;
}

#include <iowow/iwlog.h>
#include "http_server.h"
#include "poller_adapter.h"

#include <sys/epoll.h>

static int64_t _on_poller_adapter_event(struct iwn_poller_adapter *pa, void *user_data, uint32_t events) {
  return 0;
}

static void _on_poller_adapter_dispose(struct iwn_poller_adapter *pa, void *user_data) {
}

iwrc iwn_http_server_create(const struct iwn_http_server_spec *spec_, iwn_http_server_fd_t *out_fd) {
  iwrc rc = 0;
  struct iwn_http_server_spec spec = *spec_;

  if (!spec.poller) {
    return IW_ERROR_INVALID_ARGS;
  }
  if (!spec.listen) {
    spec.listen = "localhost";
  }
  if (!spec.port) {
    spec.port = spec.https ? 8443 : 8080;
  }


  return rc;
}

iwrc iwn_http_server_request_dispose(iwn_http_server_fd_t h) {
  iwrc rc = 0;

  return rc;
}

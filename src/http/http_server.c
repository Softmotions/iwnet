#include "http_server.h"
#include "poller_adapter.h"

#include <iowow/iwlog.h>
#include <iowow/iwpool.h>

#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/epoll.h>

struct iwn_http_server_impl {
  struct iwn_http_server_spec spec;
  IWPOOL *pool;
};

static int64_t _on_poller_adapter_event(struct iwn_poller_adapter *pa, void *user_data, uint32_t events) {
  return 0;
}

static void _on_poller_adapter_dispose(struct iwn_poller_adapter *pa, void *user_data) {
}

iwrc iwn_http_server_create(const struct iwn_http_server_spec *spec_, iwn_http_server_fd_t *out_fd) {
  iwrc rc = 0;
  struct iwn_http_server_impl *impl;
  struct iwn_http_server_spec *spec;

  IWPOOL *pool = iwpool_create_empty();
  if (!pool) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  RCA(impl = iwpool_calloc(sizeof(*impl), pool), finish);
  impl->pool = pool;

  spec = &impl->spec;
  memcpy(spec, spec_, sizeof(*spec));

  if (!spec->poller) {
    rc = IW_ERROR_INVALID_ARGS;
    iwlog_ecode_error2(rc, "No poller specified");
    goto finish;
  }
  if (!spec->port) {
    spec->port = spec->https ? 8443 : 8080;
  }

finish:
  if (rc) {
    iwpool_destroy(pool);
  }
  return rc;
}

iwrc iwn_http_server_request_dispose(iwn_http_server_fd_t h) {
  iwrc rc = 0;

  return rc;
}

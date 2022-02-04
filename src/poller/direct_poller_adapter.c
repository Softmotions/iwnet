#include "direct_poller_adapter.h"

#include <iowow/iwlog.h>

#include <stdlib.h>
#include <errno.h>
#include <unistd.h>

struct pa {
  struct iwn_poller_adapter     b;
  iwn_on_poller_adapter_event   on_event;
  iwn_on_poller_adapter_dispose on_dispose;
  void *user_data;
};

static ssize_t _read(struct iwn_poller_adapter *a, uint8_t *buf, size_t len) {
  return read(a->fd, buf, len);
}

static ssize_t _write(struct iwn_poller_adapter *a, const uint8_t *buf, size_t len) {
  return write(a->fd, buf, len);
}

IW_INLINE void _destroy(struct pa *a) {
  free(a);
}

static int64_t _on_ready(const struct iwn_poller_task *t, uint32_t events) {
  struct pa *a = t->user_data;
  return a->on_event((void*) a, a->user_data, events);
}

static void _on_dispose(const struct iwn_poller_task *t) {
  struct pa *a = t->user_data;
  a->on_dispose((void*) a, a->user_data);
  _destroy(a);
}

iwrc iwn_direct_poller_adapter(
  struct iwn_poller            *p,
  int                           fd,
  iwn_on_poller_adapter_event   on_event,
  iwn_on_poller_adapter_dispose on_dispose,
  void                         *user_data,
  uint32_t                      events,
  uint32_t                      events_mod,
  long                          timeout_sec
  ) {
  iwrc rc = 0;
  struct pa *a = calloc(1, sizeof(*a));
  if (!a) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  a->b.fd = fd;
  a->b.poller = p;
  a->b.read = _read;
  a->b.write = _write;
  a->on_event = on_event;
  a->on_dispose = on_dispose;
  a->user_data = user_data;

  rc = iwn_poller_add(&(struct iwn_poller_task) {
    .fd = fd,
    .user_data = a,
    .on_ready = _on_ready,
    .on_dispose = _on_dispose,
    .timeout = timeout_sec,
    .poller = p,
    .events = events,
    .events_mod = events_mod
  });

  if (rc) {
    _destroy(a);
  }
  return rc;
}

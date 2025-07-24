#include "iwn_scheduler.h"

#include <iowow/iwlog.h>

#include <assert.h>
#include <stdlib.h>
#include <string.h>

static int64_t _on_ready(const struct iwn_poller_task *t, uint32_t events) {
  struct iwn_scheduler_spec *s = t->user_data;
  assert(s);
  s->on_cancel = 0;
  if (s->task_fn) {
    s->task_fn(s->user_data);
  }
  return -1;
}

static void _on_dispose(const struct iwn_poller_task *t) {
  assert(t);
  struct iwn_scheduler_spec *s = t->user_data;
  if (s->on_cancel) {
    s->on_cancel(s->user_data);
  }
  if (s->on_dispose) {
    s->on_dispose(s->user_data);
  }
  free(s);
}

iwrc iwn_schedule2(const struct iwn_scheduler_spec *spec, int *out_fd) {
  if (!spec || spec->timeout_ms < 1 || (!spec->task_fn && !spec->on_dispose) || !spec->poller) {
    return IW_ERROR_INVALID_ARGS;
  }
  iwrc rc = 0;
  struct iwn_scheduler_spec *task = malloc(sizeof(*task));
  RCB(finish, task);
  memcpy(task, spec, sizeof(*task));

  RCC(rc, finish, iwn_poller_add2(&(struct iwn_poller_task) {
    .poller = spec->poller,
    .on_ready = _on_ready,
    .on_dispose = _on_dispose,
    .user_data = task,
    .events = IWN_POLLTIMEOUT,
    .timeout = spec->timeout_ms
  }, out_fd));

finish:
  if (rc) {
    free(task);
  }
  return rc;
}

iwrc iwn_schedule(const struct iwn_scheduler_spec *spec) {
  return iwn_schedule2(spec, 0);
}

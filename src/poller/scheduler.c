#include "scheduler.h"

#include <iowow/iwlog.h>

#include <errno.h>
#include <assert.h>
#include <sys/timerfd.h>
#include <sys/epoll.h>
#include <stdlib.h>

static void _task_worker(void *arg) {
  struct iwn_scheduler_spec *ss = arg;
  assert(arg);
  ss->task_fn(ss->user_data);
  free(ss);
}

static int64_t _on_ready(const struct iwn_poller_task *t, uint32_t events) {
  struct iwn_scheduler_spec *s = t->user_data;
  assert(s);
  if (s->thread_pool) {
    struct iwn_scheduler_spec *ss = malloc(sizeof(*ss));
    if (ss) {
      *ss = *s;
      iwrc rc = iwtp_schedule(s->thread_pool, _task_worker, ss);
      if (rc) {
        free(ss);
        iwlog_ecode_error3(rc);
      } else {
        s->on_cancel = 0;
      }
    }
  } else {
    s->on_cancel = 0;
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
  free(s);
}

iwrc iwn_schedule(const struct iwn_scheduler_spec *spec) {
  if (!spec || spec->timeout_ms < 1 || !spec->task_fn || !spec->poller) {
    return IW_ERROR_INVALID_ARGS;
  }
  iwrc rc = 0;
  struct iwn_scheduler_spec *task = malloc(sizeof(*task));
  RCB(finish, task);
  *task = *spec;

  int fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
  RCN(finish, fd);

  RCC(rc, finish, iwn_poller_add(&(struct iwn_poller_task) {
    .poller = spec->poller,
    .fd = fd,
    .on_ready = _on_ready,
    .on_dispose = _on_dispose,
    .user_data = task,
    .events = IWN_POLLIN
  }));

  task = 0;

  if (timerfd_settime(fd, 0, &(struct itimerspec) {
    .it_value = {
      .tv_sec  = spec->timeout_ms / 1000,
      .tv_nsec = (int64_t) (spec->timeout_ms % 1000) * 1000000
    }
  }, 0) < 0) {
    rc = iwrc_set_errno(IW_ERROR_ERRNO, errno);
    iwn_poller_remove(spec->poller, fd);
  }

finish:
  if (rc) {
    free(task);
  }
  return rc;
}

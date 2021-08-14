#include "poller.h"
#include "utils/khash.h"

#include <iowow/iwutils.h>
#include <iowow/iwlog.h>
#include <iowow/iwp.h>
#include <iowow/iwtp.h>

#include <time.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <errno.h>
#include <stdatomic.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <sys/eventfd.h>
#include <sys/socket.h>

KHASH_MAP_INIT_INT(SLOTS, struct poller_slot*)

#define SLOT_REMOVE_PENDING 0x01U
#define SLOT_REMOVED        0x02U
#define SLOT_PROCESSING     0x04U

#define REF_SET_LOCKED    0x01U
#define REF_LOCKED        0x02U
#define REF_DESTROY_DEFER 0x04U

struct poller {
  int fd;
  int event_fd;               ///< fd to signal internal changes on poller.
  int timer_fd;               ///< fd to set up timeouts
  int fds_count;              ///< Numbver of active file descriptors
  int max_poll_events;        ///< Max wait epoll_wait fd events at once

  long timeout_next;             ///< Next timeout check
  atomic_long timeout_checktime; ///< Last time of timeout check

  khash_t(SLOTS) * slots;
  IWTP tp;
  pthread_mutex_t mtx;
  volatile bool   stop;
  volatile bool   housekeeping;        ///< CAS barrier for timeout cleaner
};

struct poller_slot {
  int      fd;                                               ///< File descriptor beeng polled
  void    *user_data;                                        ///< Arbitrary user data associated with poller_task
  int64_t  (*on_ready)(const struct poller_task*, uint32_t); ///< On fd event ready
  void     (*on_dispose)(const struct poller_task*);         ///< On destroy handler
  uint32_t events;                                           ///< Default epoll monitoring events
  uint32_t events_mod;
  long     timeout_sec;                                      ///< Optional slot timeout
  struct poller *poller;                                     ///< Poller

  int      refs;
  uint32_t events_processing;
  uint32_t events_update;
  uint32_t flags;
  atomic_long timeout_limit;           ///< Limit in seconds for use with time function.

  struct poller_slot *next;
  bool destroy_cas;
};

IW_INLINE time_t _time_sec() {
  struct timespec t;
  clock_gettime(CLOCK_MONOTONIC_COARSE, &t);
  return t.tv_sec;
}

static void _slot_destroy(struct poller_slot *s) {
  if (__sync_bool_compare_and_swap(&s->destroy_cas, false, true)) {  // Avoid recursion
    if (s->on_dispose) {
      s->on_dispose((void*) s);
    }
    int fd = s->fd;
    if (fd > -1) {
      s->fd = -1;
      shutdown(fd, SHUT_RDWR);
      close(fd);
    }
    free(s);
  }
}

static bool _slot_unref(struct poller_slot *s, uint8_t flags) {
  struct poller *p = s->poller;
  if (!(flags & REF_LOCKED)) {
    pthread_mutex_lock(&p->mtx);
  }
  bool destroy = --s->refs == 0;
  if (destroy) {
    s->flags |= SLOT_REMOVED;
    epoll_ctl(p->fd, EPOLL_CTL_DEL, s->fd, 0);
    khiter_t k = kh_get(SLOTS, p->slots, s->fd);
    if (k != kh_end(p->slots)) {
      s = kh_value(p->slots, k);
      kh_del(SLOTS, p->slots, k);
      --p->fds_count;
    }
  }
  if (!(flags & (REF_SET_LOCKED | REF_LOCKED))) {
    pthread_mutex_unlock(&p->mtx);
  }
  if (destroy && !(flags & (REF_DESTROY_DEFER | REF_SET_LOCKED | REF_LOCKED))) {
    _slot_destroy(s);
  }
  return destroy;
}

static iwrc _slot_ref(struct poller_slot *s) {
  struct poller *p = s->poller;
  struct poller_slot *old = 0;
  bool old_destroy = false;
  iwrc rc = 0;

  pthread_mutex_lock(&p->mtx);
  if (s->flags & SLOT_REMOVED) {
    return IW_ERROR_INVALID_STATE;
  }
  if (s->refs++ == 0) {
    khiter_t k = kh_get(SLOTS, p->slots, s->fd);
    if (k != kh_end(p->slots)) {
      iwlog_error("FD: %d is in the pool already", s->fd);
      old = kh_val(p->slots, k);
      kh_value(p->slots, k) = s;
      old_destroy = _slot_unref(old, REF_LOCKED);
    } else {
      int rci;
      k = kh_put(SLOTS, p->slots, s->fd, &rci);
      if (rci != -1) {
        kh_value(p->slots, k) = s;
        ++p->fds_count;
      } else {
        rc = IW_ERROR_FAIL;
      }
    }
  }
  pthread_mutex_unlock(&p->mtx);
  if (old_destroy) {
    _slot_destroy(old);
  }
  return rc;
}

static struct poller_slot* _slot_ref_id(struct poller *p, int fd, uint8_t flags) {
  struct poller_slot *s = 0;
  if (!(flags & REF_LOCKED)) {
    pthread_mutex_lock(&p->mtx);
  }
  khiter_t k = kh_get(SLOTS, p->slots, fd);
  if (k != kh_end(p->slots)) {
    s = kh_value(p->slots, k);
  }
  if (s) {
    if (s->flags & SLOT_REMOVED) {
      s = 0;
    } else {
      ++s->refs;
    }
  }
  if (!(flags & (REF_SET_LOCKED | REF_LOCKED))) {
    pthread_mutex_unlock(&p->mtx);
  }
  return s;
}

static inline struct poller_slot* _slot_peek_leave_locked(struct poller *p, int fd) {
  struct poller_slot *s = 0;
  pthread_mutex_lock(&p->mtx);
  khiter_t k = kh_get(SLOTS, p->slots, fd);
  if (k != kh_end(p->slots)) {
    s = kh_value(p->slots, k);
  }
  return s;
}

static iwrc _slot_remove_unref(struct poller *p, int fd) {
  struct poller_slot *s = _slot_peek_leave_locked(p, fd);
  if (!s || (s->flags & SLOT_REMOVE_PENDING)) {
    pthread_mutex_unlock(&p->mtx);
    return IW_ERROR_INVALID_STATE;
  }
  s->flags |= SLOT_REMOVE_PENDING;
  bool destroy = _slot_unref(s, REF_LOCKED);
  if (!destroy) {
    destroy = _slot_unref(s, REF_LOCKED);
  }
  pthread_mutex_unlock(&p->mtx);
  if (destroy) {
    _slot_destroy(s);
  }
  return 0;
}

void poller_remove(struct poller *p, int fd) {
  struct poller_slot *s = _slot_peek_leave_locked(p, fd);
  if (!s) {
    pthread_mutex_unlock(&p->mtx);
    close(fd);
    return;
  }
  if (s->flags & SLOT_REMOVE_PENDING) {
    pthread_mutex_unlock(&p->mtx);
    return;
  }
  s->flags |= SLOT_REMOVE_PENDING;
  bool destroy = _slot_unref(s, REF_LOCKED);
  pthread_mutex_unlock(&p->mtx);
  if (destroy) {
    _slot_destroy(s);
  }
}

static void _poller_cleanup(struct poller *p) {
  pthread_mutex_lock(&p->mtx);
  int i = 0;
  int sz = kh_size(p->slots);
  int *fds = calloc(sz, sizeof(int));
  for (khiter_t k = kh_begin(p->slots); k != kh_end(p->slots) && i < sz; ++k) {
    if (!kh_exist(p->slots, k)) {
      continue;
    }
    fds[i++] = kh_key(p->slots, k);
  }
  pthread_mutex_unlock(&p->mtx);
  while (--i >= 0) {
    poller_remove(p, fds[i]);
  }
  free(fds);
}

static void _destroy(struct poller *p) {
  if (p) {
    poller_shutdown_request(p);
    iwtp_shutdown(&p->tp, true);
    _poller_cleanup(p);
    if (p->fd > -1) {
      close(p->fd);
    }
    if (p->timer_fd > -1) {
      close(p->timer_fd);
    }
    if (p->event_fd > -1) {
      close(p->event_fd);
    }
    if (p->slots) {
      kh_destroy(SLOTS, p->slots);
    }
    pthread_mutex_destroy(&p->mtx);
    free(p);
  }
}

static void _timer_ready_impl(struct poller *p) {
  time_t ctime = _time_sec();
  time_t timeout_next = ctime + 24 * 60 * 60;
  if (ctime != p->timeout_checktime) {
    p->timeout_checktime = ctime;
    struct poller_slot *h = 0;
    pthread_mutex_lock(&p->mtx);
    for (khiter_t k = kh_begin(p->slots); k != kh_end(p->slots); ++k) {
      if (!kh_exist(p->slots, k)) {
        continue;
      }
      struct poller_slot *s = kh_value(p->slots, k);
      if (s->timeout_limit <= ctime) {
        ++s->refs;
        s->timeout_limit = INT_MAX;
        s->next = h;
      } else if (s->timeout_limit < timeout_next) {
        timeout_next = s->timeout_limit;
      }
    }
    p->timeout_next = timeout_next;
    pthread_mutex_unlock(&p->mtx);

    while (h) {
      struct poller_slot *n = h->next;
      _slot_remove_unref(p, h->fd);
      h = n;
    }
  }

  struct itimerspec next = { { 0, 0 }, { timeout_next - ctime, 0 } };
  timerfd_settime(p->timer_fd, 0, &next, 0);
}

IW_INLINE int64_t _timer_ready(const struct poller_task *t, uint32_t events) {
  struct poller *p = t->poller;
  if (__sync_bool_compare_and_swap(&p->housekeeping, false, true)) {
    _timer_ready_impl(p);
    __sync_bool_compare_and_swap(&p->housekeeping, true, false);
  }
  return 0;
}

IW_INLINE void _timer_check(const struct poller_task *t, time_t time_limit) {
  if (time_limit < t->poller->timeout_next) {
    _timer_ready(t, 0);
  }
}

iwrc poller_arm_events(struct poller *p, int fd, uint32_t events) {
  int rci = 0;
  struct epoll_event ev = { 0 };
  ev.events = events;
  ev.data.fd = fd;
  struct poller_slot *s = _slot_peek_leave_locked(p, fd);
  if (s) {
    if (s->flags & SLOT_PROCESSING) {
      s->events_update |= ev.events;
    } else {
      ev.events |= s->events_mod;
      rci = epoll_ctl(p->fd, EPOLL_CTL_MOD, fd, &ev);
    }
  }
  pthread_mutex_unlock(&p->mtx);
  if (rci == -1) {
    return iwrc_set_errno(IW_ERROR_IO_ERRNO, errno);
  }
  return 0;
}

iwrc poller_add(const struct poller_task *task) {
  if (!task || task->fd < 0 || !task->poller) {
    return IW_ERROR_INVALID_ARGS;
  }
  iwrc rc = 0;
  struct poller *p = task->poller;
  assert(p);
  struct poller_slot *s = calloc(1, sizeof(*s));
  if (!s) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  memcpy(s, task, sizeof(*task));

  if (s->refs != 0) {
    rc = IW_ERROR_INVALID_STATE;
    goto finish;
  }
  RCC(rc, finish, _slot_ref(s));

  struct epoll_event ev = { 0 };
  ev.events = s->events | s->events_mod;
  ev.data.fd = s->fd;

  if (epoll_ctl(p->fd, EPOLL_CTL_ADD, s->fd, &ev) < 0) {
    rc = iwrc_set_errno(IW_ERROR_IO_ERRNO, errno);
    poller_remove(p, s->fd);
    goto finish;
  }

  _timer_check((void*) s, s->timeout_limit);

finish:
  if (rc) {
    _slot_destroy(s);
  }
  return rc;
}

void poller_shutdown_request(struct poller *p) {
  if (p && __sync_bool_compare_and_swap(&p->stop, false, true)) {
    if (p->event_fd > 0) {
      int64_t data = 1;
      write(p->event_fd, &data, sizeof(data));
    }
  }
}

void poller_shutdown_wait(struct poller *p) {
  iwtp_shutdown(&p->tp, true);
}

void poller_destroy(struct poller **pp) {
  if (pp && *pp) {
    _destroy(*pp);
    *pp = 0;
  }
}

static iwrc _create(int num_threads, int max_poll_events, struct poller **out_poller) {
  iwrc rc = 0;
  struct poller *p = calloc(1, sizeof(*p));
  if (!p) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  p->fd = -1;
  p->timer_fd = -1;
  p->event_fd = -1;
  p->max_poll_events = max_poll_events;

  pthread_mutex_init(&p->mtx, 0);
  RCA(p->slots = kh_init(SLOTS), finish);
  RCC(rc, finish, iwtp_start("poller-tp-", num_threads, 0, &p->tp));
  RCN(finish, p->fd = epoll_create1(EPOLL_CLOEXEC));
  RCN(finish, p->timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC | TFD_NONBLOCK));
  RCN(finish, p->event_fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK));
#if EFD_CLOEXEC == 0
  RCN(finish, fcntl(p->event_fd, F_SETFD, FD_CLOEXEC));
#endif

finish:
  if (rc) {
    _destroy(p);
  } else {
    *out_poller = p;
  }
  return rc;
}

iwrc poller_create(int num_threads, int max_poll_events, struct poller **out_poller) {
  if (!out_poller || max_poll_events > 1024 || num_threads > 1024) {
    return IW_ERROR_INVALID_ARGS;
  }
  *out_poller = 0;
  struct poller *p;

  if (num_threads < 1) {
    num_threads = iwp_num_cpu_cores();
  }
  if (num_threads < 1) {
    num_threads = 2;
  }
  if (max_poll_events < 1) {
    max_poll_events = 1;
  }

  iwrc rc = RCR(_create(num_threads, max_poll_events, &p));

  RCC(rc, finish, poller_add(&(struct poller_task) {
    .poller = p,
    .fd = p->event_fd,
    .events = EPOLLIN
  }));

  RCC(rc, finish, poller_add(&(struct poller_task) {
    .poller = p,
    .fd = p->timer_fd,
    .on_ready = _timer_ready,
    .events = EPOLLIN
  }));

finish:
  if (rc) {
    _destroy(p);
  } else {
    *out_poller = p;
  }
  return rc;
}

static void _worker_fn(void *arg) {
  int64_t n;
  int rci = 0;
  bool destroy = false;
  struct poller_slot *s = arg;
  struct poller *p = s->poller;

  struct epoll_event ev = { 0 };
  ev.data.fd = s->fd;
  ev.events = s->events_processing;

start:
  if (s->on_ready) {
    n = s->on_ready((void*) s, ev.events);
  } else {
    n = 0;
  }
  if (n < 0) {
    rci = -1;
    destroy = _slot_unref(s, REF_DESTROY_DEFER);
    goto finish;
  } else if (n > 0) {
    ev.events = (uint32_t) n;
  } else {
    ev.events = s->events;
  }
  pthread_mutex_lock(&p->mtx);
  if (s->events_update) {
    ev.events = s->events_update;
    s->events_update = 0;
    pthread_mutex_unlock(&p->mtx);
    goto start;
  }
  s->flags &= ~SLOT_PROCESSING;
  ev.events |= s->events_mod;

  rci = epoll_ctl(p->fd, EPOLL_CTL_MOD, ev.data.fd, &ev);
  destroy = _slot_unref(s, REF_LOCKED);
  pthread_mutex_unlock(&p->mtx);

finish:
  if (destroy) {
    _slot_destroy(s);
  } else {
    if (rci < 0) {
      poller_remove(p, ev.data.fd);
    } else if (s->timeout_sec > 0) {
      s->timeout_limit = _time_sec() + s->timeout_sec;
      _timer_check((void*) s, s->timeout_limit);
    }
  }
}

void poller_poll(struct poller *p) {
  int max_events = p->max_poll_events;
  struct epoll_event event[max_events];

  for (bool active = !p->stop && p->fds_count > 0; active; active = !p->stop && p->fds_count > 0) {
    int nfds = epoll_wait(p->fd, event, max_events, -1);
    if (nfds < 0) {
      if (errno != EINTR) {
        iwlog_ecode_error3(iwrc_set_errno(IW_ERROR_ERRNO, errno));
        break;
      } else {
        continue;
      }
    }
    for (int i = 0; i < nfds; ++i) {
      int fd = event[i].data.fd;
      if (event[i].events & (EPOLLRDHUP | EPOLLHUP | EPOLLERR)) {
        poller_remove(p, fd);
        continue;
      }
      struct poller_slot *s = _slot_ref_id(p, fd, REF_SET_LOCKED);
      if (!s) {
        pthread_mutex_unlock(&p->mtx);
        continue;
      } else if (s->flags & SLOT_PROCESSING) {
        s->events_update |= event[i].events;
        bool destroy = _slot_unref(s, REF_LOCKED);
        pthread_mutex_unlock(&p->mtx);
        if (destroy) {
          _slot_destroy(s);
        }
        continue;
      } else {
        s->flags |= SLOT_PROCESSING;
        s->events_update = 0;
        s->events_processing = event[i].events;
        s->timeout_limit = INT_MAX;
      }
      pthread_mutex_unlock(&p->mtx);

      if (iwtp_schedule(p->tp, _worker_fn, s)) {
        _slot_remove_unref(p, fd);
      }
    }
  }
  // Close all polled descriptors
  _poller_cleanup(p);
}

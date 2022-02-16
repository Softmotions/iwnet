#include "poller.h"
#include "utils/khash.h"

#include <iowow/iwutils.h>
#include <iowow/iwlog.h>
#include <iowow/iwp.h>
#include <iowow/iwtp.h>

#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <errno.h>
#include <stdatomic.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <sys/socket.h>

#if defined(IWN_KQUEUE)
#include <sys/event.h>
#elif defined(IWN_EPOLL)
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <sys/eventfd.h>
#endif

KHASH_MAP_INIT_INT(SLOTS, struct poller_slot*)

#define SLOT_REMOVE_PENDING 0x01U
#define SLOT_REMOVED        0x02U
#define SLOT_PROCESSING     0x04U

#define REF_SET_LOCKED    0x01U
#define REF_LOCKED        0x02U
#define REF_DESTROY_DEFER 0x04U

struct iwn_poller {
  int fd;
#ifdef IWN_EPOLL
  int event_fd;               ///< fd to signal internal changes on poller.
  int timer_fd;               ///< fd to set up timeouts
#endif

#ifdef IWN_KQUEUE
  int identity_seq;
#endif

  int fds_count;              ///< Numbver of active file descriptors
  int max_poll_events;        ///< Max wait epoll_wait fd events at once

  atomic_long timeout_next;      ///< Next timeout check
  atomic_long timeout_checktime; ///< Last time of timeout check

  khash_t(SLOTS) * slots;
  IWTP tp;
  pthread_mutex_t mtx;
  volatile bool   stop;
  volatile bool   housekeeping;        ///< CAS barrier for timeout cleaner
};

struct poller_slot {
  int      fd;                                                   ///< File descriptor beeng polled
  void    *user_data;                                            ///< Arbitrary user data associated with poller_task
  int64_t  (*on_ready)(const struct iwn_poller_task*, uint32_t); ///< On fd event ready
  void     (*on_dispose)(const struct iwn_poller_task*);         ///< On destroy handler
  uint32_t events;                                               ///< Default epoll monitoring events
  uint32_t events_mod;
  long     timeout;                                      ///< Optional slot timeout
  struct iwn_poller *poller;                             ///< Poller

  int      refs;
  uint32_t events_processing;
  uint32_t events_update;
  uint32_t events_armed;
  uint32_t flags;
  atomic_long timeout_limit;           ///< Limit in seconds for use with time function.

  struct poller_slot *next;
  bool destroy_cas;
};

IW_INLINE time_t _time_sec() {
  struct timespec t;
#if defined(__linux__)
  clock_gettime(CLOCK_MONOTONIC_COARSE, &t);
#elif defined(__APPLE__)
  clock_gettime(CLOCK_MONOTONIC, &t);
#else
  clock_gettime(CLOCK_MONOTONIC_FAST, &t);
#endif
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

#ifdef IWN_KQUEUE

IW_INLINE unsigned short _events_to_kflags(uint32_t events) {
  unsigned short action = EV_ENABLE;
  if (events & IWN_POLLET) {
    action |= EV_CLEAR;
  }
  if (events & IWN_POLLONESHOT) {
    action |= EV_ONESHOT;
  }
  return action;
}

IW_INLINE void _rw_fd_unsubscribe(int pfd, int fd) {
  struct kevent ev[] = {
    { fd, EVFILT_READ,  EV_DELETE },
    { fd, EVFILT_WRITE, EV_DELETE },
  };
  kevent(pfd, ev, sizeof(ev) / sizeof(ev[0]), 0, 0, 0);
}

IW_INLINE void _service_fds_unsubcribe(struct iwn_poller *p) {
  if (p->fd > -1) {
    struct kevent ev = {
      p->fd, EVFILT_TIMER, EV_DELETE
    };
    kevent(p->fd, &ev, 1, 0, 0, 0);
  }
}

#else

IW_INLINE void _rw_fd_unsubscribe(int pfd, int fd) {
  epoll_ctl(pfd, EPOLL_CTL_DEL, fd, 0);
}

#endif

static bool _slot_unref(struct poller_slot *s, uint8_t flags) {
  struct iwn_poller *p = s->poller;
  if (!(flags & REF_LOCKED)) {
    pthread_mutex_lock(&p->mtx);
  }
  bool destroy = --s->refs == 0;
  if (destroy) {
    _rw_fd_unsubscribe(p->fd, s->fd);
    s->flags |= SLOT_REMOVED;
    khiter_t k = kh_get(SLOTS, p->slots, s->fd);
    if (k != kh_end(p->slots)) {
      s = kh_value(p->slots, k);
      kh_del(SLOTS, p->slots, k);
      --p->fds_count;
#if defined(IWN_EPOLL)
      if (p->fds_count < 3) {
#elif defined(IWN_KQUEUE)
      if (p->fds_count < 1) {
#endif
        iwn_poller_shutdown_request(p);
      }
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
  struct iwn_poller *p = s->poller;
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
      iwlog_error("FD: %d is in the poller already", s->fd);
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

static struct poller_slot* _slot_ref_id(struct iwn_poller *p, int fd, uint8_t flags) {
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

static inline struct poller_slot* _slot_peek_leave_locked(struct iwn_poller *p, int fd) {
  struct poller_slot *s = 0;
  pthread_mutex_lock(&p->mtx);
  khiter_t k = kh_get(SLOTS, p->slots, fd);
  if (k != kh_end(p->slots)) {
    s = kh_value(p->slots, k);
  }
  return s;
}

static iwrc _slot_remove_unref(struct iwn_poller *p, int fd) {
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

void iwn_poller_remove(struct iwn_poller *p, int fd) {
  struct poller_slot *s = _slot_peek_leave_locked(p, fd);
  if (!s) {
    pthread_mutex_unlock(&p->mtx);
    if (fd > -1) {
      close(fd);
    }
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

static void _poller_cleanup(struct iwn_poller *p) {
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
    iwn_poller_remove(p, fds[i]);
  }
  free(fds);
}

static void _destroy(struct iwn_poller *p) {
  if (p) {
    iwn_poller_shutdown_request(p);
    iwtp_shutdown(&p->tp, true);
    _poller_cleanup(p);

#if defined(IWN_EPOLL)
    if (p->fd > -1) {
      close(p->fd);
    }
    if (p->timer_fd > -1) {
      close(p->timer_fd);
    }
    if (p->event_fd > -1) {
      close(p->event_fd);
    }
#elif defined(IWN_KQUEUE)
    _service_fds_unsubcribe(p);
#endif

    if (p->slots) {
      kh_destroy(SLOTS, p->slots);
    }
    pthread_mutex_destroy(&p->mtx);
    free(p);
  }
}

static void _timer_ready_impl(struct iwn_poller *p) {
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
        h = s;
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

#if defined(IWN_EPOLL)
  {
    struct itimerspec next = { { 0, 0 }, { timeout_next - ctime, 0 } };
    timerfd_settime(p->timer_fd, 0, &next, 0);
  }
#elif defined(IWN_KQUEUE)
  {
    struct kevent ev = {
      .ident  = p->fd,
      .filter = EVFILT_TIMER,
      .flags  = EV_ADD | EV_ENABLE | EV_CLEAR | EV_ONESHOT,
      .fflags = NOTE_SECONDS,
      .data   = timeout_next - ctime,
    };
    if (kevent(p->fd, &ev, 1, 0, 0, 0) == -1) {
      iwrc rc = iwrc_set_errno(IW_ERROR_ERRNO, errno);
      iwlog_ecode_error3(rc);
    }
  }
#endif
}

IW_INLINE int64_t _timer_ready(const struct iwn_poller_task *t, uint32_t events) {
  struct iwn_poller *p = t->poller;
  if (__sync_bool_compare_and_swap(&p->housekeeping, false, true)) {
    _timer_ready_impl(p);
    __sync_bool_compare_and_swap(&p->housekeeping, true, false);
  }
  return 0;
}

static int64_t _timer_ready_fd(const struct iwn_poller_task *t, uint32_t events) {
  uint64_t buf;
  while (read(t->fd, &buf, sizeof(buf)) != -1);
  return _timer_ready(t, events);
}

IW_INLINE void _timer_check(const struct iwn_poller_task *t, time_t time_limit) {
  long timeout_next = t->poller->timeout_next;
  if (time_limit < timeout_next || timeout_next == 0) {
    _timer_ready(t, 0);
  }
}

#if defined(IWN_KQUEUE)

iwrc iwn_poller_arm_events(struct iwn_poller *p, int fd, uint32_t events) {
  int rci = 0;
  struct poller_slot *s = _slot_peek_leave_locked(p, fd);
  if (s) {
    if (s->flags & SLOT_PROCESSING) {
      s->events_armed |= events;
    } else {
      events |= s->events_mod;
      unsigned short ka = _events_to_kflags(events);
      struct kevent ev[2];
      if (events & IWN_POLLIN) {
        ev[rci++] = (struct kevent) {
          fd, EVFILT_READ, EV_ADD | ka
        };
      }
      if (events & IWN_POLLOUT) {
        ev[rci++] = (struct kevent) {
          fd, EVFILT_WRITE, EV_ADD | ka | EV_DISPATCH
        };
      }
      if (rci > 0) {
        rci = kevent(p->fd, ev, rci, 0, 0, 0);
      }
    }
  }
  pthread_mutex_unlock(&p->mtx);
  if (rci == -1) {
    return iwrc_set_errno(IW_ERROR_IO_ERRNO, errno);
  }
  return 0;
}

#elif defined(IWN_EPOLL)

iwrc iwn_poller_arm_events(struct iwn_poller *p, int fd, uint32_t events) {
  int rci = 0;
  struct epoll_event ev = { 0 };
  ev.events = events;
  ev.data.fd = fd;
  struct poller_slot *s = _slot_peek_leave_locked(p, fd);
  if (s) {
    if (s->flags & SLOT_PROCESSING) {
      s->events_armed |= ev.events;
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

#endif

#if defined(IWN_KQUEUE)

static int _next_kevent_identity(struct poller_slot *s) {
  int ret;
  pthread_mutex_lock(&s->poller->mtx);
  if (s->poller->identity_seq == INT_MIN || s->poller->identity_seq >= 0) {
    s->poller->identity_seq = -1;
  }
  ret = --s->poller->identity_seq;
  pthread_mutex_unlock(&s->poller->mtx);
  return ret;
}

#endif

static iwrc _poller_timeout_create_fd(struct poller_slot *s) {
  s->timeout_limit = INT_MAX;
  if (s->timeout < 1) {
    return IW_ERROR_INVALID_ARGS;
  }
  #if defined(IWN_KQUEUE)
  s->fd = _next_kevent_identity(s);
  #elif defined(IWN_EPOLL)
  s->fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
  if (s->fd < 0) {
    return iwrc_set_errno(IW_ERROR_ERRNO, errno);
  }
  #endif
  return 0;
}

static iwrc _poller_timeout_add(struct poller_slot *s) {
#if defined(IWN_KQUEUE)
  struct kevent ev = {
    (unsigned) s->fd, EVFILT_TIMER, EV_ADD | EV_ONESHOT, NOTE_USECONDS, ((int64_t) s->timeout) * 1000
  };
  if (kevent(s->poller->fd, &ev, 1, 0, 0, 0) == -1) {
    return iwrc_set_errno(IW_ERROR_ERRNO, errno);
  }
#elif defined(IWN_EPOLL)
  struct epoll_event ev = { 0 };
  ev.events = EPOLLIN | EPOLLET | EPOLLONESHOT;
  ev.data.fd = s->fd;

  if (epoll_ctl(s->poller->fd, EPOLL_CTL_ADD, s->fd, &ev) == -1) {
    return iwrc_set_errno(IW_ERROR_IO_ERRNO, errno);
  }
  if (timerfd_settime(s->fd, 0, &(struct itimerspec) {
    .it_value = {
      .tv_sec  = s->timeout / 1000,
      .tv_nsec = (int64_t) (s->timeout % 1000) * 1000000
    }
  }, 0) < 0) {
    return iwrc_set_errno(IW_ERROR_ERRNO, errno);
  }
#endif
  return 0;
}

iwrc iwn_poller_add(const struct iwn_poller_task *task) {
  if (!task || !task->poller || (!(task->events & IWN_POLLTIMEOUT) && task->fd < 0)) {
    return IW_ERROR_INVALID_ARGS;
  }
  iwrc rc;
  struct iwn_poller *p = task->poller;
  struct poller_slot *s = calloc(1, sizeof(*s));
  if (!s) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  memcpy(s, task, sizeof(*task));

  if (task->events & IWN_POLLTIMEOUT) {
    s->fd = -1;
    rc = _poller_timeout_create_fd(s);
    if (rc) {
      free(s);
      return rc;
    }
  }

  rc = _slot_ref(s);
  if (rc) {
    if (s->fd > -1 && s->fd != task->fd) {
      close(s->fd);
    }
    free(s);
    return rc;
  }

  if (IW_UNLIKELY(task->events & IWN_POLLTIMEOUT)) {
    rc = _poller_timeout_add(s);
  } else {
#if defined(IWN_KQUEUE)

    int i = 0;
    struct kevent ev[2];
    uint32_t events = s->events | s->events_mod;
    unsigned short ka = _events_to_kflags(events);

    if (events & IWN_POLLIN) {
      ev[i++] = (struct kevent) {
        s->fd, EVFILT_READ, EV_ADD | ka
      };
    }
    if (events & IWN_POLLOUT) {
      ev[i++] = (struct kevent) {
        s->fd, EVFILT_WRITE, EV_ADD | ka | EV_DISPATCH
      };
    }
    if (i > 0 && kevent(p->fd, ev, i, 0, 0, 0) == -1) {
      rc = iwrc_set_errno(IW_ERROR_IO_ERRNO, errno);
      goto finish;
    }

#elif defined(IWN_EPOLL)

    struct epoll_event ev = { 0 };
    ev.events = s->events | s->events_mod;
    ev.data.fd = s->fd;

    if (epoll_ctl(p->fd, EPOLL_CTL_ADD, s->fd, &ev) == -1) {
      rc = iwrc_set_errno(IW_ERROR_IO_ERRNO, errno);
      goto finish;
    }

#endif

    if (s->timeout > 0) {
      s->timeout_limit = _time_sec() + s->timeout;
      _timer_check((void*) s, s->timeout_limit);
    } else {
      s->timeout_limit = INT_MAX;
    }
  }

finish:
  if (rc) {
    s->on_dispose = 0;
    iwn_poller_remove(p, s->fd);
  }
  return rc;
}

void iwn_poller_set_timeout(struct iwn_poller *p, int fd, long timeout_sec) {
  struct poller_slot *s = _slot_peek_leave_locked(p, fd);
  if (!s || s->timeout == timeout_sec || (s->events & IWN_POLLTIMEOUT)) {
    pthread_mutex_unlock(&p->mtx);
    return;
  }
  if (timeout_sec > 0) {
    s->timeout = timeout_sec;
    s->timeout_limit = _time_sec() + s->timeout;
  } else {
    s->timeout = 0;
    s->timeout_limit = INT_MAX;
  }
  pthread_mutex_unlock(&p->mtx);
  if (timeout_sec > 0) {
    _timer_check((void*) s, s->timeout_limit);
  }
}

void iwn_poller_poke(struct iwn_poller *p) {
#if defined(IWN_KQUEUE)
  {
    struct kevent ev[] = {
      { p->fd, EVFILT_USER, EV_ADD | EV_ONESHOT },
      { p->fd, EVFILT_USER, 0, NOTE_TRIGGER     }
    };
    if (kevent(p->fd, ev, sizeof(ev) / sizeof(ev[0]), 0, 0, 0) == -1) {
      iwlog_ecode_error3(iwrc_set_errno(IW_ERROR_ERRNO, errno));
    }
  }
#elif defined(IWN_EPOLL)
  if (p->event_fd > 0) {
    int64_t data = 1;
    if (write(p->event_fd, &data, sizeof(data)) == -1) {
      iwlog_ecode_error3(iwrc_set_errno(IW_ERROR_IO_ERRNO, errno));
    }
  }
#endif
}

void iwn_poller_shutdown_request(struct iwn_poller *p) {
  if (p && __sync_bool_compare_and_swap(&p->stop, false, true)) {
    iwn_poller_poke(p);
  }
}

void iwn_poller_shutdown_wait(struct iwn_poller *p) {
  iwtp_shutdown(&p->tp, true);
}

void iwn_poller_destroy(struct iwn_poller **pp) {
  if (pp && *pp) {
    struct iwn_poller *p = *pp;
    *pp = 0;
    _destroy(p);
  }
}

#if defined(IWN_EPOLL)

static void _on_eventfd_dispose(const struct iwn_poller_task *t) {
  t->poller->event_fd = -1;
}

static iwrc _eventfd_ensure(struct iwn_poller *p) {
  iwrc rc = 0;
  if (p->event_fd > -1) {
    return 0;
  }
  RCN(finish, p->event_fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK));
   #if EFD_CLOEXEC == 0
#endif
  RCN(finish, fcntl(p->event_fd, F_SETFD, FD_CLOEXEC));
  RCC(rc, finish, iwn_poller_add(&(struct iwn_poller_task) {
    .poller = p,
    .fd = p->event_fd,
    .on_dispose = _on_eventfd_dispose,
    .events = IWN_POLLIN
  }));

finish:
  return rc;
}

static void _on_timerfd_dispose(const struct iwn_poller_task *t) {
  t->poller->timer_fd = -1;
}

static iwrc _timerfd_ensure(struct iwn_poller *p) {
  iwrc rc = 0;
  if (p->timer_fd > -1) {
    return 0;
  }
  RCN(finish, p->timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC | TFD_NONBLOCK));
  RCC(rc, finish, iwn_poller_add(&(struct iwn_poller_task) {
    .poller = p,
    .fd = p->timer_fd,
    .on_ready = _timer_ready_fd,
    .on_dispose = _on_timerfd_dispose,
    .events = IWN_POLLIN,
    .events_mod = IWN_POLLET
  }));

finish:
  return rc;
}

#endif

static iwrc _create(int num_threads, int max_poll_events, struct iwn_poller **out_poller) {
  iwrc rc = 0;
  struct iwn_poller *p = calloc(1, sizeof(*p));
  if (!p) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  p->fd = -1;
#ifdef IWN_EPOLL
  p->timer_fd = -1;
  p->event_fd = -1;
#endif
  p->max_poll_events = max_poll_events;

  pthread_mutex_init(&p->mtx, 0);
  RCA(p->slots = kh_init(SLOTS), finish);
  RCC(rc, finish, iwtp_start("poller-tp-", num_threads, 0, &p->tp));

#if defined(IWN_KQUEUE)
  RCN(finish, p->fd = kqueue());
#elif defined(IWN_EPOLL)
  RCN(finish, p->fd = epoll_create1(EPOLL_CLOEXEC));
  RCC(rc, finish, _eventfd_ensure(p));
  RCC(rc, finish, _timerfd_ensure(p));
#endif

finish:
  if (rc) {
    _destroy(p);
  } else {
    *out_poller = p;
  }
  return rc;
}

iwrc iwn_poller_create(int num_threads, int max_poll_events, struct iwn_poller **out_poller) {
  if (!out_poller || max_poll_events > 1024 || num_threads > 1024) {
    return IW_ERROR_INVALID_ARGS;
  }
  *out_poller = 0;
  if (num_threads < 1) {
    num_threads = iwp_num_cpu_cores();
  }
  if (num_threads < 1) {
    num_threads = 2;
  }
  if (max_poll_events < 1) {
    max_poll_events = 1;
  }

  return _create(num_threads, max_poll_events, out_poller);
}

static void _worker_fn(void *arg) {
  int64_t n;
  int rci = 0;
  bool destroy = false;
  struct poller_slot *s = arg;
  struct iwn_poller *p = s->poller;
  uint32_t events = s->events_processing;
  int fd = s->fd;

start:

  if (s->on_ready) {
    n = s->on_ready((void*) s, events);
  } else {
    n = 0;
  }
  if (s->events & IWN_POLLTIMEOUT) {
    n = -1;
  }
  if (n < 0) {
    rci = -1;
    destroy = _slot_unref(s, REF_DESTROY_DEFER);
    goto finish;
  } else if (n > 0) {
    events = (uint32_t) n;
  } else {
    events = s->events;
  }
  pthread_mutex_lock(&p->mtx);
  if (s->events_update) {
    events = s->events_update;
    s->events_update = 0;
    pthread_mutex_unlock(&p->mtx);
    goto start;
  }
  s->flags &= ~SLOT_PROCESSING;
  events = events | s->events_mod | s->events_armed;
  s->events_armed = 0;

#if defined(IWN_KQUEUE)
  {
    unsigned short ka = _events_to_kflags(events);
    struct kevent ev[2];
    if (events & IWN_POLLIN) {
      ev[rci++] = (struct kevent) {
        fd, EVFILT_READ, EV_ADD | ka
      };
    }
    if (events & IWN_POLLOUT) {
      ev[rci++] = (struct kevent) {
        fd, EVFILT_WRITE, EV_ADD | ka | EV_DISPATCH
      };
    }
    if (rci > 0) {
      rci = kevent(p->fd, ev, rci, 0, 0, 0);
    }
  }
#elif defined(IWN_EPOLL)
  struct epoll_event ev = { 0 };
  ev.data.fd = fd;
  ev.events = events;
  rci = epoll_ctl(p->fd, EPOLL_CTL_MOD, ev.data.fd, &ev);
#endif

  destroy = _slot_unref(s, REF_LOCKED);
  pthread_mutex_unlock(&p->mtx);

finish:
  if (destroy) {
    _slot_destroy(s);
  } else {
    if (rci < 0) {
      iwn_poller_remove(p, fd);
    } else if (s->timeout > 0) {
      s->timeout_limit = _time_sec() + s->timeout;
      _timer_check((void*) s, s->timeout_limit);
    }
  }
}

bool iwn_poller_alive(struct iwn_poller *p) {
  return p && !p->stop;
}

iwrc iwn_poller_task(struct iwn_poller *p, void (*task)(void*), void *arg) {
  return iwtp_schedule(p->tp, task, arg);
}

bool iwn_poller_probe(struct iwn_poller *p, int fd, iwn_poller_probe_fn probe, void *fn_user_data) {
  struct poller_slot *s = _slot_ref_id(p, fd, 0);
  if (s) {
    probe(p, s->user_data, fn_user_data);
    _slot_unref(s, 0);
    return true;
  } else {
    return false;
  }
}

void iwn_poller_poll(struct iwn_poller *p) {
  int max_events = p->max_poll_events;

#if defined(IWN_KQUEUE)
  p->stop = p->fds_count < 1;
  struct kevent event[max_events];
#elif defined(IWN_EPOLL)
  _eventfd_ensure(p);
  _timerfd_ensure(p);
  p->stop = p->fds_count < 3;
  struct epoll_event event[max_events];
#endif

  while (!p->stop) {
#if defined(IWN_KQUEUE)
    int nfds = kevent(p->fd, 0, 0, event, max_events, 0);
#elif defined(IWN_EPOLL)
    int nfds = epoll_wait(p->fd, event, max_events, -1);
#endif
    if (nfds < 0) {
      if (errno != EINTR) {
        iwlog_ecode_error3(iwrc_set_errno(IW_ERROR_ERRNO, errno));
        break;
      } else {
        continue;
      }
    }
    for (int i = 0; i < nfds; ++i) {
      int fd;
      uint32_t events = 0;

#if defined(IWN_KQUEUE)
      if (event[i].ident == (uintptr_t) -1) {
        continue;
      }
      fd = (int) event[i].ident;
      if (fd == p->fd) { // Own, not fd related event
        if (event[i].filter == EVFILT_TIMER) {
          if (__sync_bool_compare_and_swap(&p->housekeeping, false, true)) {
            _timer_ready_impl(p);
            __sync_bool_compare_and_swap(&p->housekeeping, true, false);
          }
        }
        continue;
      }
      switch (event[i].filter) {
        case EVFILT_READ:
          events |= IWN_POLLIN;
          break;
        case EVFILT_WRITE:
          events |= IWN_POLLOUT;
          break;
      }
      if (event[i].flags & (EV_EOF | EV_ERROR)) {
        iwn_poller_remove(p, fd);
        continue;
      }

#elif defined(IWN_EPOLL)
      fd = event[i].data.fd;
      events = event[i].events;
      if (events & (EPOLLRDHUP | EPOLLHUP | EPOLLERR)) {
        iwn_poller_remove(p, fd);
        continue;
      }
#endif

      struct poller_slot *s = _slot_ref_id(p, fd, REF_SET_LOCKED);
      if (!s) {
        pthread_mutex_unlock(&p->mtx);
        continue;
      } else if (s->flags & SLOT_PROCESSING) {
        s->events_update |= events;
        bool destroy = _slot_unref(s, REF_LOCKED);
        pthread_mutex_unlock(&p->mtx);
        if (destroy) {
          _slot_destroy(s);
        }
        continue;
      } else {
        s->flags |= SLOT_PROCESSING;
        s->events_update = 0;
        s->events_processing = events;
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

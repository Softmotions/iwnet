#include "iwn_poller.h"

#include <iowow/iwutils.h>
#include <iowow/iwlog.h>
#include <iowow/iwp.h>
#include <iowow/iwtp.h>
#include <iowow/iwhmap.h>
#include <iowow/iwth.h>
#include <iowow/iwarr.h>

#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <errno.h>
#include <stdatomic.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <limits.h>
#include <string.h>
#include <sys/socket.h>

#if defined(IWN_KQUEUE)
#include <sys/event.h>
#elif defined(IWN_EPOLL)
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <sys/eventfd.h>
#endif

#define SLOT_REMOVE_PENDING 0x01U
#define SLOT_REMOVED        0x02U
#define SLOT_PROCESSING     0x04U
#define SLOT_UNSUBSCRIBED   0x08U

#define REF_SET_LOCKED    0x01U
#define REF_LOCKED        0x02U
#define REF_DESTROY_DEFER 0x04U

struct iwn_poller {
  int fd;
#ifdef IWN_EPOLL
  int event_fd;        ///< fd to signal internal changes on poller.
  int timer_fd;        ///< fd to set up timeouts
#endif

#ifdef IWN_KQUEUE
  int identity_seq;
#endif

  int fds_count;              ///< Numbver of active file descriptors
  int max_poll_events;        ///< Max wait epoll_wait fd events at once

  atomic_long timeout_next;      ///< Next timeout check
  atomic_long timeout_checktime; ///< Last time of timeout check

  IWTP tp;
  struct iwhmap *slots;
  char *thread_name;

  struct iwulist destroy_hooks; // void (*hook)(struct iwn_poller*)

  pthread_mutex_t    mtx;
  pthread_barrier_t  _barrier_poll; ///< Poll-in-thread barrier
  pthread_barrier_t *barrier_poll;
  uint32_t flags;                 ///< Poller mode flags. See iwn_poller_flags_set()

  volatile bool stop;
  volatile bool housekeeping;          ///< CAS barrier for timeout cleaner
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
  bool abort;
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
    if (s->fd > -1) {
      shutdown(s->fd, SHUT_RDWR);
      close(s->fd);
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

IW_INLINE void _rw_fd_unsubscribe(struct poller_slot *s) {
  if (!(s->flags & SLOT_UNSUBSCRIBED)) {
    s->flags |= SLOT_UNSUBSCRIBED;
    struct kevent ev[] = {
      { s->fd, EVFILT_READ, EV_DELETE },
      { s->fd, EVFILT_WRITE, EV_DELETE },
    };
    kevent(s->poller->fd, ev, sizeof(ev) / sizeof(ev[0]), 0, 0, 0);
  }
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

IW_INLINE void _rw_fd_unsubscribe(struct poller_slot *s) {
  if (!(s->flags & SLOT_UNSUBSCRIBED)) {
    s->flags |= SLOT_UNSUBSCRIBED;
    epoll_ctl(s->poller->fd, EPOLL_CTL_DEL, s->fd, 0);
  }
}

#endif

static bool _slot_unref(struct poller_slot *s, uint8_t flags) {
  struct iwn_poller *p = s->poller;
  if (!(flags & REF_LOCKED)) {
    pthread_mutex_lock(&p->mtx);
  }
  if (s->flags & SLOT_REMOVED) {
    pthread_mutex_unlock(&p->mtx);
    return false;
  }
  --s->refs;
  bool destroy = s->refs == 0;
  if (destroy) {
    s->flags |= SLOT_REMOVED;
    _rw_fd_unsubscribe(s);
    if (iwhmap_remove_u32(p->slots, s->fd)) {
      --p->fds_count;
#if defined(IWN_EPOLL)
      if (p->fds_count < 3 && !(p->flags & IWN_POLLER_POLL_NO_FDS)) {
#elif defined(IWN_KQUEUE)
      if (p->fds_count < 1 && !(p->flags & IWN_POLLER_POLL_NO_FDS)) {
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
  iwrc rc = 0;
  struct iwn_poller *p = s->poller;
  pthread_mutex_lock(&p->mtx);
  if (++s->refs == 1) {
    struct poller_slot *os = iwhmap_get_u32(p->slots, s->fd);
    if (os) {
      pthread_mutex_unlock(&p->mtx);
      iwlog_error("FD: %d is managed already, poller: %d", s->fd, p->fd);
      return IW_ERROR_INVALID_STATE;
    }
    rc = iwhmap_put_u32(p->slots, s->fd, s);
    if (!rc) {
      ++p->fds_count;
    }
  }
  pthread_mutex_unlock(&p->mtx);
  return rc;
}

static struct poller_slot* _slot_ref_id(struct iwn_poller *p, int fd, uint8_t flags) {
  struct poller_slot *s;
  if (!(flags & REF_LOCKED)) {
    pthread_mutex_lock(&p->mtx);
  }
  s = iwhmap_get_u32(p->slots, fd);
  if (s) {
    if (s->flags & (SLOT_REMOVED | SLOT_REMOVE_PENDING)) {
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

IW_INLINE struct poller_slot* _slot_peek_leave_locked(struct iwn_poller *p, int fd) {
  pthread_mutex_lock(&p->mtx);
  return iwhmap_get_u32(p->slots, fd);
}

static void _slot_remove_unref(struct iwn_poller *p, int fd) {
  struct poller_slot *s = _slot_peek_leave_locked(p, fd);
  if (!s || (s->flags & (SLOT_REMOVE_PENDING | SLOT_REMOVED))) {
    pthread_mutex_unlock(&p->mtx);
    return;
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
  return;
}

void iwn_poller_remove(struct iwn_poller *p, int fd) {
  if (!p) {
    return;
  }
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
  _rw_fd_unsubscribe(s);
  bool destroy = _slot_unref(s, REF_LOCKED);
  pthread_mutex_unlock(&p->mtx);
  if (destroy) {
    _slot_destroy(s);
  }
}

static void _poller_cleanup(struct iwn_poller *p) {
  int *fds, i;
  int buf[1024];
  struct iwhmap_iter iter;

  pthread_mutex_lock(&p->mtx);
  uint32_t sz = iwhmap_count(p->slots);
  if (sz <= sizeof(buf) / sizeof(buf[0])) {
    fds = buf;
  } else {
    fds = calloc(sz, sizeof(*fds));
    if (!fds) {
      pthread_mutex_unlock(&p->mtx);
      return;
    }
  }
  iwhmap_iter_init(p->slots, &iter);
  for (i = 0; iwhmap_iter_next(&iter); ++i) {
    fds[i] = (int) (intptr_t) iter.key;
  }
  pthread_mutex_unlock(&p->mtx);

  while (--i >= 0) {
    iwn_poller_remove(p, fds[i]);
  }

  if (fds != buf) {
    free(fds);
  }
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

    for (int i = 0, l = iwulist_length(&p->destroy_hooks); i < l; ++i) {
      iwn_poller_destroy_hook h = *(iwn_poller_destroy_hook*) iwulist_get(&p->destroy_hooks, i);
      h(p);
    }

    iwulist_destroy_keep(&p->destroy_hooks);
    iwhmap_destroy(p->slots);
    pthread_mutex_destroy(&p->mtx);
    free(p);
  }
}

static void _timer_ready_impl(struct iwn_poller *p) {
  time_t ctime = _time_sec();
  time_t timeout_next = ctime + 24L * 60 * 60;

  if (ctime != p->timeout_checktime) {
    struct iwhmap_iter iter;
    struct poller_slot *h = 0;
    p->timeout_checktime = ctime;

    pthread_mutex_lock(&p->mtx);
    iwhmap_iter_init(p->slots, &iter);
    while (iwhmap_iter_next(&iter)) {
      struct poller_slot *s = (struct poller_slot*) iter.val;
      if (!(s->flags & (SLOT_REMOVED | SLOT_REMOVE_PENDING | SLOT_PROCESSING))) {
        if (s->timeout_limit <= ctime) {
          ++s->refs;
          s->timeout_limit = INT_MAX;
          s->next = h;
          h = s;
        } else if (s->timeout_limit < timeout_next) {
          timeout_next = s->timeout_limit;
        }
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
      .ident = p->fd,
      .filter = EVFILT_TIMER,
      .flags = EV_ADD | EV_ENABLE | EV_CLEAR | EV_ONESHOT,
      .fflags = NOTE_SECONDS,
      .data = timeout_next - ctime,
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
  if (s && !s->abort) {
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
  if (s && !s->abort) {
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
      .tv_sec = s->timeout / 1000,
      .tv_nsec = (int64_t) (s->timeout % 1000) * 1000000
    }
  }, 0) < 0) {
    return iwrc_set_errno(IW_ERROR_ERRNO, errno);
  }
#endif
  return 0;
}

iwrc iwn_poller_add2(const struct iwn_poller_task *task, int *out_fd) {
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
    if ((task->events & IWN_POLLTIMEOUT) && s->fd > -1) {
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
  } else if (out_fd) {
    *out_fd = s->fd;
  }
  return rc;
}

iwrc iwn_poller_add(const struct iwn_poller_task *task) {
  return iwn_poller_add2(task, 0);
}

bool iwn_poller_fd_is_managed(struct iwn_poller *p, int fd) {
  bool ret;
  pthread_mutex_lock(&p->mtx);
  ret = iwhmap_get_u32(p->slots, fd) != 0;
  pthread_mutex_unlock(&p->mtx);
  return ret;
}

bool iwn_poller_fd_ref(struct iwn_poller *p, int fd, int refs) {
  bool ret = false, destroy = false;
  pthread_mutex_lock(&p->mtx);
  struct poller_slot *s = iwhmap_get_u32(p->slots, fd);
  if (s) {
    ret = true;
    s->refs += refs;
    destroy = s->refs == 0;
    if (destroy) {
      s->flags |= SLOT_REMOVED;
      _rw_fd_unsubscribe(s);
      if (iwhmap_remove_u32(p->slots, s->fd)) {
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
  }
  pthread_mutex_unlock(&p->mtx);
  if (destroy) {
    _slot_destroy(s);
  }
  return ret;
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
#if defined(NOTE_TRIGGER)
      { p->fd, EVFILT_USER, 0, NOTE_TRIGGER }
#elif defined(EV_TRIGGER)
      { p->fd, EVFILT_USER, EV_TRIGGER, 0 }
#else
#error "Either NOTE_TRIGGER or EV_TRIGGER is required."
#endif
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

void iwn_poller_destroy(struct iwn_poller **pp) {
  if (pp && *pp) {
    _destroy(*pp);
    *pp = 0;
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
  int fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
  RCN(finish, fd);
  p->event_fd = fd;

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
  int fd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC | TFD_NONBLOCK);
  RCN(finish, fd);
  p->timer_fd = fd;

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

static iwrc _create(const struct iwn_poller_spec *spec_, struct iwn_poller **out_poller) {
  if (!out_poller || !spec_) {
    return IW_ERROR_INVALID_ARGS;
  }
  struct iwn_poller_spec spec = *spec_;
  *out_poller = 0;

  if (spec.num_threads < 1) {
    spec.num_threads = 2;
  }
  if (spec.one_shot_events < 1) {
    spec.one_shot_events = 1;
  }
  if (spec.one_shot_events > 128) {
    spec.one_shot_events = 128;
  }

  iwrc rc = 0;
  struct iwn_poller *p = calloc(1, sizeof(*p));
  if (!p) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  p->fd = -1;
  p->stop = true;
  p->flags = spec.flags & (IWN_POLLER_POLL_NO_FDS);
#ifdef IWN_EPOLL
  p->timer_fd = -1;
  p->event_fd = -1;
#endif
  p->max_poll_events = spec.one_shot_events;
  p->destroy_hooks.usize = sizeof(iwn_poller_destroy_hook);

  RCN(finish, pthread_mutex_init(&p->mtx, 0));
  RCB(finish, p->slots = iwhmap_create_u32(0));
  RCC(rc, finish, iwtp_start_by_spec(&(struct iwtp_spec) {
    .num_threads = spec.num_threads,
    .overflow_threads_factor = spec.overflow_threads_factor,
    .queue_limit = spec.queue_limit,
    .thread_name_prefix = "poller-tp-",
    .warn_on_overflow_thread_spawn = spec.warn_on_overflow_thread_spawn,
  }, &p->tp));

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

iwrc iwn_poller_create_by_spec(const struct iwn_poller_spec *spec, struct iwn_poller **out_poller) {
  return _create(spec, out_poller);
}

iwrc iwn_poller_create(int num_threads, int one_shot_events, struct iwn_poller **out_poller) {
  return _create(&(struct iwn_poller_spec) {
    .num_threads = num_threads,
    .one_shot_events = one_shot_events,
  }, out_poller);
}

static void _worker_fn(void *arg) {
  int64_t n;
  int rci = 0;
  long timeout = 0;
  bool destroy = false, abort = false;
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
  abort = s->abort;
  if (s->events_update) {
    events = s->events_update;
    s->events_update = 0;
    pthread_mutex_unlock(&p->mtx);
    goto start;
  }

  s->flags &= ~SLOT_PROCESSING;
  events = events | s->events_mod | s->events_armed;
  s->events_armed = 0;

  if (!abort) {
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
  }

  destroy = _slot_unref(s, REF_LOCKED);
  timeout = s->timeout;
  pthread_mutex_unlock(&p->mtx);

finish:
  if (destroy) {
    _slot_destroy(s);
  } else if (abort || rci < 0) {
    iwn_poller_remove(p, fd);
  } else if (timeout > 0) {
    long timeout_limit = _time_sec() + timeout;
    s->timeout_limit = timeout_limit;
    _timer_check((void*) s, timeout_limit);
  }
}

iwrc iwn_poller_add_destroy_hook(struct iwn_poller *poller, iwn_poller_destroy_hook hook) {
  if (!hook || !poller) {
    return IW_ERROR_INVALID_ARGS;
  }
  return iwulist_push(&poller->destroy_hooks, &hook);
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

static void* _poll_worker(void *d) {
  struct iwn_poller *p = d;
  iwn_poller_poll(p);
  return 0;
}

iwrc iwn_poller_poll_in_thread(struct iwn_poller *p, const char *thr_name, pthread_t *out_thr) {
  iwrc rc = 0;
  if (thr_name) {
    p->thread_name = strdup(thr_name);
  }
  RCN(finish, pthread_barrier_init(&p->_barrier_poll, 0, 2));
  p->barrier_poll = &p->_barrier_poll;
  RCN(finish, pthread_create(out_thr, 0, _poll_worker, p));
  pthread_barrier_wait(p->barrier_poll);

finish:
  if (p->barrier_poll) {
    pthread_barrier_destroy(p->barrier_poll);
    p->barrier_poll = 0;
  }
  return rc;
}

void iwn_poller_flags_set(struct iwn_poller *p, uint32_t flags) {
  p->flags = flags;
}

void iwn_poller_poll(struct iwn_poller *p) {
  p->stop = false;
  if (p->thread_name) {
    iwp_set_current_thread_name(p->thread_name);
    free(p->thread_name);
    p->thread_name = 0;
  }

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

  if (p->flags & IWN_POLLER_POLL_NO_FDS) {
    p->stop = false;
  }

  if (p->barrier_poll) {
    pthread_barrier_wait(p->barrier_poll);
  }

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
      bool abort = false;

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
        abort = true;
      }

#elif defined(IWN_EPOLL)
      fd = event[i].data.fd;
      events = event[i].events;
      if (events & (EPOLLRDHUP | EPOLLHUP | EPOLLERR)) {
        events &= ~(EPOLLRDHUP | EPOLLHUP | EPOLLERR);
        abort = true;
      }
#endif

      struct poller_slot *s = _slot_ref_id(p, fd, REF_SET_LOCKED);
      if (IW_UNLIKELY(!s)) {
        pthread_mutex_unlock(&p->mtx);
        if (abort) {
          iwn_poller_remove(p, fd);
        }
        continue;
      } else if (IW_UNLIKELY(!events)) {
        bool destroy = _slot_unref(s, REF_LOCKED);
        if (abort) {
          s->abort = true;
        } else {
          abort = s->abort;
        }
        pthread_mutex_unlock(&p->mtx);
        if (destroy) {
          _slot_destroy(s);
        } else if (abort) {
          iwn_poller_remove(p, fd);
        }
        continue;
      } else if (s->flags & SLOT_PROCESSING) {
        if (abort) {
          s->abort = true;
        }
        s->events_update |= events;
        bool destroy = _slot_unref(s, REF_LOCKED);
        pthread_mutex_unlock(&p->mtx);
        if (destroy) {
          _slot_destroy(s);
        }
        continue;
      } else {
        if (abort) {
          s->abort = true;
        }
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

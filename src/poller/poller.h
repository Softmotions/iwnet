#pragma once

#include <iowow/basedefs.h>

#include <stdint.h>

IW_EXTERN_C_START

#if defined(__FreeBSD__) || defined(__APPLE__) || defined(__NetBSD__) || defined(__OpenBSD__)
#define IWN_KQUEUE
#endif

#ifdef __linux__
#include <sys/epoll.h>
#define IWN_POLLIN  EPOLLIN
#define IWN_POLLOUT EPOLLOUT
#define IWN_POLLET  EPOLLET
#elif defined(IWN_KQUEUE)
#error "Kqueue is not yet supported"
#else
#error "Unsupported operating system"
#endif

struct iwn_poller;

struct iwn_poller_task {                                         // !!! Sync fields with poller.c
  int      fd;                                                   ///< File descriptor beeng polled
  void    *user_data;                                            ///< Arbitrary user data associated with poller_task
  int64_t  (*on_ready)(const struct iwn_poller_task*, uint32_t); ///< On fd event ready
  void     (*on_dispose)(const struct iwn_poller_task*);         ///< On destroy handler
  uint32_t events;                                               ///< Initial poll monitoring events
  uint32_t events_mod;                                           ///< Extra event flags added for every poll rearm
  long     timeout_sec;                                          ///< Fd activity timeout
  struct iwn_poller *poller;                                     ///< Poller
};

IW_EXPORT iwrc iwn_poller_create(int num_threads, int one_shot_events, struct iwn_poller **out_poller);

IW_EXPORT iwrc iwn_poller_add(const struct iwn_poller_task *task);

IW_EXPORT iwrc iwn_poller_arm_events(struct iwn_poller *poller, int fd, uint32_t events);

IW_EXPORT void iwn_poller_set_timeout(struct iwn_poller *poller, int fd, long timeout_sec);

IW_EXPORT void iwn_poller_remove(struct iwn_poller *poller, int fd);

IW_EXPORT void iwn_poller_shutdown_request(struct iwn_poller *p);

IW_EXPORT void iwn_poller_shutdown_wait(struct iwn_poller *p);

IW_EXPORT void iwn_poller_destroy(struct iwn_poller **pp);

IW_EXPORT iwrc iwn_poller_task(struct iwn_poller *p, void (*task)(void*), void *arg);

IW_EXPORT void iwn_poller_poll(struct iwn_poller *p);

IW_EXPORT bool iwn_poller_alive(struct iwn_poller *p);

IW_EXTERN_C_END

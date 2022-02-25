#pragma once

#include <iowow/basedefs.h>

#include <stdint.h>

IW_EXTERN_C_START

#if defined(__FreeBSD__) || defined(__APPLE__) || defined(__NetBSD__) || defined(__OpenBSD__)
#define IWN_KQUEUE
#endif

/// Poller will do oneshot execution of `on_ready()` handler
/// after the period of time in milliseconds specified in `(struct iwn_poller_task).timeout` field.
#define IWN_POLLTIMEOUT (1U << 21)
//#define IWN_POLLABORT   (1U << 22)

#ifdef __linux__
#define IWN_EPOLL
#include <sys/epoll.h>
#define IWN_POLLIN      EPOLLIN
#define IWN_POLLOUT     EPOLLOUT
#define IWN_POLLONESHOT EPOLLONESHOT
#define IWN_POLLET      EPOLLET
#elif defined(IWN_KQUEUE)
#define IWN_POLLIN      0x01U
#define IWN_POLLOUT     0x02U
#define IWN_POLLONESHOT 0x04U
#define IWN_POLLET      0x08U
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
  long     timeout;                                              ///< Max event channel inactivity timeout in seconds.
                                                                 ///  Or timeout in milliseconds in IWN_POLLTIMEOUT
                                                                 ///  mode.
  struct iwn_poller *poller;                                     ///< Poller
};

typedef void (*iwn_poller_probe_fn)(struct iwn_poller*, void *slot_user_data, void *fn_user_data);

IW_EXPORT iwrc iwn_poller_create(int num_threads, int one_shot_events, struct iwn_poller **out_poller);

IW_EXPORT iwrc iwn_poller_add(const struct iwn_poller_task *task);

IW_EXPORT iwrc iwn_poller_arm_events(struct iwn_poller*, int fd, uint32_t events);

IW_EXPORT void iwn_poller_set_timeout(struct iwn_poller*, int fd, long timeout_sec);

IW_EXPORT void iwn_poller_remove(struct iwn_poller*, int fd);

IW_EXPORT void iwn_poller_poke(struct iwn_poller*);

IW_EXPORT void iwn_poller_shutdown_request(struct iwn_poller*);

IW_EXPORT void iwn_poller_destroy(struct iwn_poller **pp);

IW_EXPORT iwrc iwn_poller_task(struct iwn_poller*, void (*task)(void*), void *arg);

IW_EXPORT void iwn_poller_poll(struct iwn_poller*);

IW_EXPORT bool iwn_poller_alive(struct iwn_poller*);

IW_EXPORT bool iwn_poller_probe(struct iwn_poller*, int fd, iwn_poller_probe_fn probe, void *fn_user_data);

IW_EXTERN_C_END
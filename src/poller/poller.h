#pragma once

#include <iowow/basedefs.h>

#include <stdint.h>

struct poller;

struct poller_task {                                         // !!! Sync fields with poller.c
  int      fd;                                               ///< File descriptor beeng polled
  void    *user_data;                                        ///< Arbitrary user data associated with poller_task
  int64_t  (*on_ready)(const struct poller_task*, uint32_t); ///< On fd event ready
  void     (*on_dispose)(const struct poller_task*);         ///< On destroy handler
  uint32_t events;                                           ///< Initial poll monitoring events
  uint32_t events_mod;                                       ///< Extra event flags added for every poll rearm
  long     timeout_sec;                                      ///< Optional slot timeout
  struct poller *poller;                                     ///< Poller
};

iwrc poller_create(int num_threads, int one_shot_events, struct poller **out_poller);

iwrc poller_add(const struct poller_task *task);

iwrc poller_arm_events(struct poller *poller, int fd, uint32_t events);

void poller_remove(struct poller *poller, int fd);

void poller_shutdown_request(struct poller *p);

void poller_destroy(struct poller **pp);

void poller_poll(struct poller *p);

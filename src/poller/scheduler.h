#pragma once

#include "poller.h"
#include <iowow/iwtp.h>

typedef void (*scheduler_task_f)(void *arg);

struct scheduler_spec {
  scheduler_task_f task_fn;  ///< Task execution function.
  void *user_data;           ///< User data passed to `task_fn()` function.
  struct poller *poller;     ///< Poller
  uint32_t       timeout_ms; ///< Task timeout in milliseconds
  IWTP thread_pool;          ///< Thread pool used for `task_fn()` execution. Optional.
};

iwrc schedule(const struct scheduler_spec *spec);

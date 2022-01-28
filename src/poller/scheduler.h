#pragma once

#include "poller.h"
#include <iowow/iwtp.h>

IW_EXTERN_C_START;

typedef void (*iwn_scheduler_task_f)(void *arg);

struct iwn_scheduler_spec {
  iwn_scheduler_task_f task_fn;  ///< Task execution function.
  void  (*on_cancel)(void*); ///< Optional on_cancel handler before timeout event
  void *user_data;           ///< User data passed to `task_fn()` function.
  struct iwn_poller *poller;     ///< Poller
  uint32_t       timeout_ms; ///< Task timeout in milliseconds
  IWTP thread_pool;          ///< Thread pool used for `task_fn()` execution. Optional.
};

IW_EXPORT iwrc iwn_schedule(const struct iwn_scheduler_spec *spec);

IW_EXTERN_C_END;

#pragma once

/// Excutes delayed tasks after specified timeout.

#include "iwn_poller.h"
#include <iowow/iwtp.h>

IW_EXTERN_C_START

/// Task execute callback.
typedef void (*iwn_scheduler_task_f)(void *arg);

/// Delayed task spe.
struct iwn_scheduler_spec {
  iwn_scheduler_task_f task_fn; ///< Task execute callback.
  void (*on_cancel)(void*);     ///< Optional on_cancel handler.
                                ///  Called when pending task execution will be cancelled for
                                ///  some reason. Eg: poller shutdown.

  void  (*on_dispose)(void*);   ///< Optional dispose handler. Called when task is removed from event poller.
  void *user_data;              ///< User data passed to `task_fn()` function.
  struct iwn_poller *poller;    ///< Poller.
  uint32_t timeout_ms;          ///< Task timeout in milliseconds.
};

/// Submits delayed task for execution.
IW_EXPORT iwrc iwn_schedule(const struct iwn_scheduler_spec *spec);

IW_EXPORT iwrc iwn_schedule2(const struct iwn_scheduler_spec *spec, int *out_fd);

IW_EXTERN_C_END

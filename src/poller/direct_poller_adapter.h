#pragma once

#include "poller_adapter.h"

iwrc direct_poller_adapter_create(
  struct poller            *p,
  int                       fd,
  on_poller_adapter_event   on_event,
  on_poller_adapter_dispose on_dispose,
  void                     *user_data,
  uint32_t                  events,
  uint32_t                  events_mod,
  long                      timeout_sec);

#pragma once

#include "poller_adapter.h"

IW_EXTERN_C_START

IW_EXPORT iwrc iwn_direct_poller_adapter(
  struct iwn_poller            *p,
  int                           fd,
  iwn_on_poller_adapter_event   on_event,
  iwn_on_poller_adapter_dispose on_dispose,
  void                         *user_data,
  uint32_t                      events,
  uint32_t                      events_mod,
  long                          timeout_sec);

IW_EXTERN_C_END

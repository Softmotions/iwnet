#pragma once

#include "poller.h"

struct iwn_poller_adapter;

typedef int64_t (*iwn_on_poller_adapter_event)(struct iwn_poller_adapter *pa, void *user_data, uint32_t events);

typedef void (*iwn_on_poller_adapter_dispose)(struct iwn_poller_adapter *pa, void *user_data);

struct iwn_poller_adapter {
  struct iwn_poller *poller;
  ssize_t (*read)(struct iwn_poller_adapter *a, uint8_t *buf, size_t len);
  ssize_t (*write)(struct iwn_poller_adapter *a, const uint8_t *buf, size_t len);
  int     fd;
};

#pragma once

#include "poller.h"

struct poller_adapter;

typedef int64_t (*on_poller_adapter_event)(struct poller_adapter *pa, void *user_data, uint32_t events);

typedef void (*on_poller_adapter_dispose)(struct poller_adapter *pa, void *user_data);

struct poller_adapter {
  struct poller *poller;
  ssize_t (*read)(struct poller_adapter *a, uint8_t *buf, size_t len);
  ssize_t (*write)(struct poller_adapter *a, const uint8_t *buf, size_t len);
  int     fd;
};

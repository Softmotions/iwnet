#pragma once

#include <stdlib.h>
#include <stdbool.h>
#include <stdatomic.h>

#include <iowow/iwlog.h>

static atomic_int iwn_asserts_failed;

#define IWN_ASSERT_FATAL(v__) \
  if (!(v__)) { \
    iwlog_error2("Assertion failed: "#v__); \
    exit(1); \
  }

#define IWN_ASSERT(v__) \
  if (!(v__)) { \
    ++iwn_asserts_failed; \
    iwlog_error2("Assertion failed: "#v__); \
  }

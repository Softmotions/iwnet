#pragma once

#include <iowow/basedefs.h>
#include <iowow/iwp.h>
#include <iowow/iwutils.h>

IW_EXTERN_C_START;

static bool iwn_is_zero(void *p, size_t len) {
  for (size_t i = 0; i < len; ++i) {
    if (*((char*) p + i) != 0) {
      return false;
    }
  }
  return true;
}

static char* iwn_argument_or_file(char *arg) {
  if (!arg || *arg == '\0') {
    return 0;
  }
  if (*arg == '@') {
    return iwu_file_read_as_buf(arg + 1);
  } else {
    return arg;
  }
}

static iwrc iwn_ts(int64_t *out) {
  iwrc rc;
  uint64_t llv;
  if ((rc = iwp_current_time_ms(&llv, false)) == 0) {
    *out = llv;
    return 0;
  } else {
    *out = 0;
    return rc;
  }
}

IW_EXTERN_C_END;

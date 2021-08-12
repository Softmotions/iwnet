#pragma once

#include <iowow/basedefs.h>
#include <iowow/iwp.h>
#include <iowow/iwutils.h>

static bool utils_is_zero(void *p, size_t len) {
  for (size_t i = 0; i < len; ++i) {
    if (*((char*) p + i) != 0) {
      return false;
    }
  }
  return true;
}

static char* utils_argument_or_file(char *arg) {
  if (!arg || *arg == '\0') {
    return 0;
  }
  if (*arg == '@') {
    return iwu_file_read_as_buf(arg + 1);
  } else {
    return arg;
  }
}

static iwrc utils_ts(int64_t *out) {
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

static char* utils_bin2hex(
  char* const                hex,
  const size_t               hex_maxlen,
  const unsigned char* const bin,
  const size_t               bin_len) {

  size_t i = (size_t) 0U;
  unsigned int x;
  int b;
  int c;

  if ((bin_len >= SIZE_MAX / 2) || (hex_maxlen <= bin_len * 2U)) {
    //errx(2, "bin2hex length wrong");
    return 0;
  }
  while (i < bin_len) {
    c = bin[i] & 0xf;
    b = bin[i] >> 4;
    x = (unsigned char) (87U + c + (((c - 10U) >> 8) & ~38U)) << 8
        | (unsigned char) (87U + b + (((b - 10U) >> 8) & ~38U));
    hex[i * 2U] = (char) x;
    x >>= 8;
    hex[i * 2U + 1U] = (char) x;
    i++;
  }
  hex[i * 2U] = 0U;
  return hex;
}


#include "codec.h"

#include <iowow/iwutils.h>

#include <string.h>
#include <stdlib.h>

IW_INLINE bool is_anum(char c) {
  return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

size_t iwn_url_encoded_len(const char *src, ssize_t src_len) {
  size_t res = 0;
  if (src_len < 0) {
    src_len = strlen(src);
  }
  for (int i = 0; i < src_len; ++i) {
    if (is_anum(src[i])) {
      res++;
    } else {
      res += 3;
    }
  }
  return res;
}

size_t iwn_url_encode(const char *src, ssize_t src_len, char *out, size_t out_size) {
  if (src_len < 0) {
    src_len = strlen(src);
  }
  static char hex[] = "0123456789ABCDEF";
  size_t n = 0;
  for (int i = 0; i < src_len; ++i) {
    if (n >= out_size) {
      break;
    }
    char c = src[i];
    if (is_anum(c)) {
      out[n++] = c;
    } else {
      if (n + 2 >= out_size) {
        break;
      }
      out[n++] = '%';
      out[n++] = hex[(c >> 4) & 0x0F];
      out[n++] = hex[c & 0x0F];
    }
  }
  if (n < out_size) {
    out[n] = '\0';
  } else if (out_size > 0) {
    out[out_size - 1] = '\0';
  }
  return n;
}

IW_ALLOC char* iwn_url_encode_new(const char *src, ssize_t src_len) {
  if (src_len < 0) {
    src_len = strlen(src);
  }
  size_t len = iwn_url_encoded_len(src, src_len);
  char *ret = malloc(len + 1);
  if (!ret) {
    return 0;
  }
  iwn_url_encode(src, src_len, ret, len + 1);
  return ret;
}

void iwn_url_decode_inplace(char *str, ssize_t str_len) {
  char *rp = str;
  char *wp = str;
  char tmp[] = { 0, 0, 0 };
  while (rp - str < str_len && *rp) {
    if (IW_UNLIKELY(*rp == '%')) {
      rp++;
      tmp[0] = *rp++;
      tmp[1] = *rp;
      *wp = (char) strtol(tmp, 0, 16);
    } else if (IW_UNLIKELY(*rp == '+')) {
      *wp = ' ';
    } else {
      *wp = *rp;
    }
    rp++;
    wp++;
  }
  *wp = '\0';
}

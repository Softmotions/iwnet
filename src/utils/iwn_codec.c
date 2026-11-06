#include "iwn_codec.h"

#include <iowow/iwutils.h>

#include <string.h>
#include <stdlib.h>
#include <limits.h>

IW_INLINE bool is_unreserved(char c) { // See rfc3986
  return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
         || c == '-' || c == '.' || c == '_' || c == '~';
}

IW_INLINE int hexval(char c) {
  if (c >= '0' && c <= '9') {
    return c - '0';
  }
  if (c >= 'a' && c <= 'f') {
    return c - 'a' + 10;
  }
  if (c >= 'A' && c <= 'F') {
    return c - 'A' + 10;
  }
  return -1;
}

size_t iwn_url_encoded_len(const char *src, ssize_t src_len) {
  size_t res = 0;
  if (src_len < 0) {
    src_len = strlen(src);
  }
  for (int i = 0; i < src_len; ++i) {
    if (is_unreserved(src[i])) {
      res++;
    } else {
      res += 3;
    }
  }
  return res;
}

size_t iwn_url_encoded_aws_len(const char *src, ssize_t src_len) {
  size_t res = 0;
  if (src_len < 0) {
    src_len = strlen(src);
  }
  for (int i = 0; i < src_len; ++i) {
    if (is_unreserved(src[i])) {
      res++;
    } else if (src[i] == '=') {
      res += 5;
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
    if (is_unreserved(c)) {
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

size_t iwn_url_encode_aws(const char *src, ssize_t src_len, char *out, size_t out_size) {
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
    if (is_unreserved(c)) {
      out[n++] = c;
    } else if (c == '=') {
      if (n + 4 >= out_size) {
        break;
      }
      out[n++] = '%';
      out[n++] = '2';
      out[n++] = '5';
      out[n++] = '3';
      out[n++] = 'D';
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

IW_ALLOC char* iwn_url_encode_printf_va(const char *fmt, va_list va) {
  char *ret = 0;
  char buf[1024];
  char *wp = buf;

  va_list cva;
  va_copy(cva, va);

  int size = vsnprintf(wp, sizeof(buf), fmt, va);
  if (size < 0) {
    // errno was set accordingly
    goto finish;
  }
  if (size >= sizeof(buf)) {
    wp = malloc(size + 1);
    if (!wp) {
      goto finish;
    }
    size = vsnprintf(wp, size + 1, fmt, cva);
    if (size < 0) {
      goto finish;
    }
  }

  ret = iwn_url_encode_new(fmt, size);

finish:
  va_end(cva);
  if (wp != buf) {
    free(wp);
  }
  return ret;
}

IW_ALLOC char* iwn_url_encode_new_printf(const char *fmt, ...) {
  va_list va;
  va_start(va, fmt);
  char *res = iwn_url_encode_printf_va(fmt, va);
  va_end(va);
  return res;
}

size_t iwn_url_decode_inplace2(char *sp, char *ep) {
  const char *rp = sp;
  char *wp = sp;
  char tmp[] = { 0, 0, 0 };
  while (rp < ep) {
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
  return rp - sp;
}

static void _url_decode_inplace(char *str, bool plus_as_space) {
  char *wp = str;
  const char *rp = str;
  while (*rp) {
    if (IW_UNLIKELY(*rp == '%') && rp[1] && rp[2]) {
      // Decode `%XX`, keep malformed escapes as is
      int h = hexval(rp[1]), l = hexval(rp[2]);
      if (h < 0 || l < 0) {
        *wp++ = *rp++;
        continue;
      }
      *wp++ = (char) ((h << 4) | l);
      rp += 3;
    } else if (plus_as_space && IW_UNLIKELY(*rp == '+')) {
      *wp++ = ' ';
      ++rp;
    } else {
      *wp++ = *rp++;
    }
  }
  *wp = '\0';
}

void iwn_url_decode_inplace(char *str) {
  _url_decode_inplace(str, true);
}

void iwn_url_decode_path_inplace(char *str) {
  _url_decode_inplace(str, false);
}

size_t iwn_unescape_backslashes_inplace(char *str, ssize_t str_len) {
  if (str_len < 0) {
    str_len = SSIZE_MAX;
  }
  const char *rp = str;
  char *wp = str;
  while (rp - str < str_len && *rp) {
    if (IW_UNLIKELY(*rp == '\\')) {
      ++rp;
      if (rp - str < str_len && *rp) {
        *wp = *rp;
      } else {
        break;
      }
    } else {
      *wp = *rp;
    }
    ++rp;
    ++wp;
  }
  return wp - str;
}

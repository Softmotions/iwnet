#include <assert.h>
#include <err.h>
#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "iwn_base64.h"

/* Base64 routines adapted from https://www.libsodium.org */

/*
 * ISC License
 *
 * Copyright (c) 2013-2017
 * Frank Denis <j at pureftpd dot org>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* Derived from original code by CodesInChaos */
static char* bin2hex(
  char* const                hex,
  const size_t               hex_maxlen,
  const unsigned char* const bin,
  const size_t               bin_len
  ) {
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

static int hex2bin(
  unsigned char* const bin,
  const size_t         bin_maxlen,
  const char* const    hex,
  const size_t         hex_len,
  const char* const    ignore,
  size_t* const        bin_len,
  const char** const   hex_end
  ) {
  size_t bin_pos = (size_t) 0U;
  size_t hex_pos = (size_t) 0U;
  int ret = 0;
  unsigned char c;
  unsigned char c_acc = 0U;
  unsigned char c_alpha0, c_alpha;
  unsigned char c_num0, c_num;
  unsigned char c_val;
  unsigned char state = 0U;

  while (hex_pos < hex_len) {
    c = (unsigned char) hex[hex_pos];
    c_num = c ^ 48U;
    c_num0 = (c_num - 10U) >> 8;
    c_alpha = (c & ~32U) - 55U;
    c_alpha0 = ((c_alpha - 10U) ^ (c_alpha - 16U)) >> 8;
    if ((c_num0 | c_alpha0) == 0U) {
      if ((ignore != 0) && (state == 0U) && (strchr(ignore, c) != 0)) {
        hex_pos++;
        continue;
      }
      break;
    }
    c_val = (c_num0 & c_num) | (c_alpha0 & c_alpha);
    if (bin_pos >= bin_maxlen) {
      ret = -1;
      errno = ERANGE;
      break;
    }
    if (state == 0U) {
      c_acc = c_val * 16U;
    } else {
      bin[bin_pos++] = c_acc | c_val;
    }
    state = ~state;
    hex_pos++;
  }
  if (state != 0U) {
    hex_pos--;
    errno = EINVAL;
    ret = -1;
  }
  if (ret != 0) {
    bin_pos = (size_t) 0U;
  }
  if (hex_end != 0) {
    *hex_end = &hex[hex_pos];
  } else if (hex_pos != hex_len) {
    errno = EINVAL;
    ret = -1;
  }
  if (bin_len != 0) {
    *bin_len = bin_pos;
  }
  return ret;
}

/*
 * Some macros for constant-time comparisons. These work over values in
 * the 0..255 range. Returned value is 0x00 on "false", 0xFF on "true".
 *
 * Original code by Thomas Pornin.
 */
#define EQ(x, y) \
        ((((0U - ((unsigned int) (x) ^ (unsigned int) (y))) >> 8) & 0xFF) ^ 0xFF)
#define GT(x, y) ((((unsigned int) (y) - (unsigned int) (x)) >> 8) & 0xFF)
#define GE(x, y) (GT(y, x) ^ 0xFF)
#define LT(x, y) GT(y, x)
#define LE(x, y) GE(y, x)

static int b64_byte_to_char(unsigned int x) {
  return (LT(x, 26) & (x + 'A'))
         | (GE(x, 26) & LT(x, 52) & (x + ('a' - 26)))
         | (GE(x, 52) & LT(x, 62) & (x + ('0' - 52))) | (EQ(x, 62) & '+')
         | (EQ(x, 63) & '/');
}

static unsigned int b64_char_to_byte(int c) {
  const unsigned int x
    = (GE(c, 'A') & LE(c, 'Z') & (c - 'A'))
      | (GE(c, 'a') & LE(c, 'z') & (c - ('a' - 26)))
      | (GE(c, '0') & LE(c, '9') & (c - ('0' - 52))) | (EQ(c, '+') & 62)
      | (EQ(c, '/') & 63);

  return x | (EQ(x, 0) & (EQ(c, 'A') ^ 0xFF));
}

static int b64_byte_to_urlsafe_char(unsigned int x) {
  return (LT(x, 26) & (x + 'A'))
         | (GE(x, 26) & LT(x, 52) & (x + ('a' - 26)))
         | (GE(x, 52) & LT(x, 62) & (x + ('0' - 52))) | (EQ(x, 62) & '-')
         | (EQ(x, 63) & '_');
}

static unsigned int b64_urlsafe_char_to_byte(int c) {
  const unsigned x
    = (GE(c, 'A') & LE(c, 'Z') & (c - 'A'))
      | (GE(c, 'a') & LE(c, 'z') & (c - ('a' - 26)))
      | (GE(c, '0') & LE(c, '9') & (c - ('0' - 52))) | (EQ(c, '-') & 62)
      | (EQ(c, '_') & 63);

  return x | (EQ(x, 0) & (EQ(c, 'A') ^ 0xFF));
}

#define VARIANT_NO_PADDING_MASK 0x2U
#define VARIANT_URLSAFE_MASK    0x4U

static int base64_check_variant(const int variant) {
  if ((((unsigned int) variant) & ~0x6U) != 0x1U) {
    //errx(2, "base64_check_variant: invalid variant");
    return 0;
  }
  return 1;
}

size_t iwn_base64_encoded_len(const size_t bin_len, const int variant) {
  if (!base64_check_variant(variant)) {
    return 0;
  }
  return base64_ENCODED_LEN(bin_len, variant);
}

char* iwn_base64_encode(
  char* const                b64,
  const size_t               b64_maxlen,
  size_t                    *out_b64_len,
  const unsigned char* const bin,
  const size_t               bin_len,
  const int                  variant
  ) {
  size_t acc_len = (size_t) 0;
  size_t b64_pos = (size_t) 0;
  size_t bin_pos = (size_t) 0;
  unsigned int acc = 0U;

  size_t b64_len = iwn_base64_encoded_len(bin_len, variant);
  if (b64_maxlen < b64_len) {
    *out_b64_len = 0;
    return 0;
  }
  if ((((unsigned int) variant) & VARIANT_URLSAFE_MASK) != 0U) {
    while (bin_pos < bin_len) {
      acc = (acc << 8) + bin[bin_pos++];
      acc_len += 8;
      while (acc_len >= 6) {
        acc_len -= 6;
        b64[b64_pos++] = (char) b64_byte_to_urlsafe_char((acc >> acc_len) & 0x3F);
      }
    }
    if (acc_len > 0) {
      b64[b64_pos++] = (char) b64_byte_to_urlsafe_char((acc << (6 - acc_len)) & 0x3F);
    }
  } else {
    while (bin_pos < bin_len) {
      acc = (acc << 8) + bin[bin_pos++];
      acc_len += 8;
      while (acc_len >= 6) {
        acc_len -= 6;
        b64[b64_pos++] = (char) b64_byte_to_char((acc >> acc_len) & 0x3F);
      }
    }
    if (acc_len > 0) {
      b64[b64_pos++] = (char) b64_byte_to_char((acc << (6 - acc_len)) & 0x3F);
    }
  }
  while (b64_pos < b64_len - 1) {
    b64[b64_pos++] = '=';
  }
  b64[b64_len - 1] = 0U;
  *out_b64_len = b64_len;
  return b64;
}

static int _base642bin_skip_padding(
  const char* const b64,
  const size_t b64_len, size_t* const b64_pos_p,
  const char* const ignore, size_t padding_len
  ) {
  int c;

  while (padding_len > 0) {
    if (*b64_pos_p >= b64_len) {
      errno = ERANGE;
      return -1;
    }
    c = b64[*b64_pos_p];
    if (c == '=') {
      padding_len--;
    } else if ((ignore == 0) || (strchr(ignore, c) == 0)) {
      errno = EINVAL;
      return -1;
    }
    (*b64_pos_p)++;
  }
  return 0;
}

int iwn_base64_decode(
  unsigned char* const bin, const size_t bin_maxlen,
  const char* const b64, const size_t b64_len,
  const char* const ignore, size_t* const bin_len,
  const char** const b64_end, const int variant
  ) {
  size_t acc_len = (size_t) 0;
  size_t b64_pos = (size_t) 0;
  size_t bin_pos = (size_t) 0;

  unsigned int is_urlsafe;
  int ret = 0;
  unsigned int acc = 0U;
  unsigned int d;
  char c;

  if (!base64_check_variant(variant)) {
    return -1;
  }
  is_urlsafe = ((unsigned int) variant) & VARIANT_URLSAFE_MASK;
  while (b64_pos < b64_len) {
    c = b64[b64_pos];
    if (is_urlsafe) {
      d = b64_urlsafe_char_to_byte(c);
    } else {
      d = b64_char_to_byte(c);
    }
    if (d == 0xFF) {
      if ((ignore != 0) && (strchr(ignore, c) != 0)) {
        b64_pos++;
        continue;
      }
      break;
    }
    acc = (acc << 6) + d;
    acc_len += 6;
    if (acc_len >= 8) {
      acc_len -= 8;
      if (bin_pos >= bin_maxlen) {
        errno = ERANGE;
        ret = -1;
        break;
      }
      bin[bin_pos++] = (acc >> acc_len) & 0xFF;
    }
    b64_pos++;
  }
  if ((acc_len > 4U) || ((acc & ((1U << acc_len) - 1U)) != 0U)) {
    ret = -1;
  } else if (  (ret == 0)
            && ((((unsigned int) variant) & VARIANT_NO_PADDING_MASK) == 0U)) {
    ret = _base642bin_skip_padding(b64, b64_len, &b64_pos, ignore,
                                   acc_len / 2);
  }
  if (ret != 0) {
    bin_pos = (size_t) 0U;
  } else if (ignore != 0) {
    while (b64_pos < b64_len && strchr(ignore, b64[b64_pos]) != 0) {
      b64_pos++;
    }
  }
  if (b64_end != 0) {
    *b64_end = &b64[b64_pos];
  } else if (b64_pos != b64_len) {
    errno = EINVAL;
    ret = -1;
  }
  if (bin_len != 0) {
    *bin_len = bin_pos;
  }
  return ret;
}

char* iwn_base64_encode_url(const void *buf, size_t buf_len, size_t *out_len) {
  size_t encoded_len = base64_ENCODED_LEN(buf_len, base64_VARIANT_URLSAFE_NO_PADDING);
  char *encoded = calloc(1, encoded_len);
  if (!encoded) {
    return 0;
  }
  return iwn_base64_encode(encoded, encoded_len, out_len, buf, buf_len, base64_VARIANT_URLSAFE_NO_PADDING);
}

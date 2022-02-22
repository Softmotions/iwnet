#include "bre_base64.h"
#include <stddef.h>

static const uint8_t base64_table[65]
  = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

uint8_t *base64_encode(
  bre_alloc     alloc,
  const uint8_t *src,
  size_t        len,
  size_t        *out_len,
  const char    *prefix,
  const char    *postfix,
  size_t        line_length) {

  uint8_t *out, *pos;
  const uint8_t *end, *in;
  size_t olen;
  int ll;

  size_t prefix_len = prefix ? strlen(prefix) : 0;
  size_t postfix_len = postfix ? strlen(postfix) : 0;

  if (line_length == 0) {
    line_length = 76;
  }

  olen = len * 4 / 3 + 4;         /* 3-byte blocks to 4-byte */
  olen += olen / line_length;     /* line feeds */
  olen++;                         /* NULL termination */

  out = alloc(olen + prefix_len + postfix_len + 2 /* \n */);
  if (out == 0) {
    return 0;
  }

  pos = out;

  if (prefix_len) {
    memcpy(out, prefix, prefix_len);
    pos += prefix_len;
    *pos++ = '\n';
  }

  end = src + len;
  in = src;
  ll = 0;

  while (end - in >= 3) {
    *pos++ = base64_table[in[0] >> 2];
    *pos++ = base64_table[((in[0] & 0x03) << 4) | (in[1] >> 4)];
    *pos++ = base64_table[((in[1] & 0x0f) << 2) | (in[2] >> 6)];
    *pos++ = base64_table[in[2] & 0x3f];
    in += 3;
    ll += 4;
    if (ll >= line_length) {
      *pos++ = '\n';
      ll = 0;
    }
  }

  if (end - in) {
    *pos++ = base64_table[in[0] >> 2];
    if (end - in == 1) {
      *pos++ = base64_table[(in[0] & 0x03) << 4];
      *pos++ = '=';
    } else {
      *pos++ = base64_table[((in[0] & 0x03) << 4)
                            | (in[1] >> 4)];
      *pos++ = base64_table[(in[1] & 0x0f) << 2];
    }
    *pos++ = '=';
    ll += 4;
  }

  if (ll) {
    *pos++ = '\n';
  }

  if (postfix_len) {
    memcpy(pos, postfix, postfix_len);
    pos += postfix_len;
    *pos++ = '\n';
  }

  *pos = '\0';
  if (out_len) {
    *out_len = pos - out;
  }

  return out;
}

uint8_t *base64_decode(
  bre_alloc     alloc,
  bre_dealloc   dealloc,
  const uint8_t *src,
  size_t        len,
  size_t        *out_len) {

  uint8_t dtable[256], block[4];
  uint8_t *out, *pos, tmp;
  size_t i, count, olen;
  int pad = 0;

  memset(dtable, 0x80, sizeof(dtable));
  for (i = 0; i < sizeof(base64_table) - 1; i++) {
    dtable[base64_table[i]] = (uint8_t) i;
  }
  dtable['='] = 0;

  count = 0;
  for (i = 0; i < len; i++) {
    if (dtable[src[i]] != 0x80) {
      count++;
    }
  }

  if ((count == 0) || count % 4) {
    return 0;
  }

  olen = count / 4 * 3;

  pos = out = alloc(olen);
  if (out == 0) {
    return 0;
  }

  count = 0;
  for (i = 0; i < len; i++) {
    tmp = dtable[src[i]];
    if (tmp == 0x80) {
      continue;
    }
    if (src[i] == '=') {
      pad++;
    }
    block[count] = tmp;
    count++;
    if (count == 4) {
      *pos++ = (block[0] << 2) | (block[1] >> 4);
      *pos++ = (block[1] << 4) | (block[2] >> 2);
      *pos++ = (block[2] << 6) | block[3];
      count = 0;
      if (pad) {
        if (pad == 1) {
          pos--;
        } else if (pad == 2) {
          pos -= 2;
        } else {
          /* Invalid padding */
          dealloc(out);
          return 0;
        }
        break;
      }
    }
  }

  *out_len = pos - out;
  return out;
}

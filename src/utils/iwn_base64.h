#pragma once

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

#include <stddef.h>
#include <iowow/basedefs.h>

IW_EXTERN_C_START;

#define base64_VARIANT_ORIGINAL            1
#define base64_VARIANT_ORIGINAL_NO_PADDING 3
#define base64_VARIANT_URLSAFE             5
#define base64_VARIANT_URLSAFE_NO_PADDING  7

/*
 * Computes the required length to encode BIN_LEN bytes as a base64 string
 * using the given variant. The computed length includes a trailing \0.
 */
#define base64_ENCODED_LEN(BIN_LEN, VARIANT)                                                       \
        (((BIN_LEN) / 3U) * 4U                                                                     \
         + ((((BIN_LEN) -((BIN_LEN) / 3U) * 3U) | (((BIN_LEN) -((BIN_LEN) / 3U) * 3U) >> 1)) & 1U) \
         * (4U - (~((((VARIANT) & 2U) >> 1) - 1U) & (3U - ((BIN_LEN) -((BIN_LEN) / 3U) * 3U)))) + 1U)

size_t iwn_base64_encoded_len(const size_t bin_len, const int variant);

char* iwn_base64_encode(
  char* const                b64,
  const size_t               b64_maxlen,
  size_t                    *out_b64_len,
  const unsigned char* const bin,
  const size_t               bin_len,
  const int                  variant)
__attribute__((nonnull(1)));

int iwn_base64_decode(
  unsigned char* const bin,
  const size_t         bin_maxlen,
  const char* const    b64,
  const size_t         b64_len,
  const char* const    ignore,
  size_t* const        bin_len,
  const char** const   b64_end,
  const int            variant)
__attribute__((nonnull(1)));

IW_EXPORT char* iwn_base64_encode_url(const void *buf, size_t buf_len, size_t *out_len);

IW_EXTERN_C_END;

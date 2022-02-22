/*
 * Base64 encoding/decoding (RFC1341)
 * Copyright (c) 2005-2011, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 */

#pragma once

#include "bre_base.h"
#pragma once

uint8_t *base64_encode(
  bre_alloc     alloc,
  const uint8_t *src,
  size_t        len,
  size_t        *out_len,
  const char    *prefix,
  const char    *postfix,
  size_t        line_length);

uint8_t *base64_decode(
  bre_alloc     alloc,
  bre_dealloc   dealloc,
  const uint8_t *src,
  size_t        len,
  size_t        *out_len);

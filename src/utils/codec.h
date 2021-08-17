#pragma once

#include <iowow/basedefs.h>
#include "base64.h"

IW_ALLOC char* iwn_url_encode_new(const char *src, size_t src_len);

void iwn_url_encode(const char *src, size_t src_len, char *tgt, size_t tgt_len);

size_t iwn_url_encoded_len(const char *src, size_t src_len);

void iwn_url_decode_inplace(char *buf);

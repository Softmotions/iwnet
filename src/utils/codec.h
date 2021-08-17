#pragma once

#include <iowow/basedefs.h>
#include "base64.h"

IW_ALLOC char* iwn_url_encode_new(const char *src, ssize_t src_len);

size_t iwn_url_encode(const char *src, ssize_t src_len, char *out, size_t out_size);

size_t iwn_url_encoded_len(const char *src, ssize_t src_len);

void iwn_url_decode_inplace(char *str, ssize_t str_len);


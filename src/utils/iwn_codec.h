#pragma once

#include <iowow/basedefs.h>
#include "iwn_base64.h"

#include <stdarg.h>

IW_EXTERN_C_START;

IW_EXPORT IW_ALLOC char* iwn_url_encode_new(const char *src, ssize_t src_len);

IW_EXPORT size_t iwn_url_encode(const char *src, ssize_t src_len, char *out, size_t out_size);

IW_EXPORT size_t iwn_url_encoded_len(const char *src, ssize_t src_len);

IW_EXPORT size_t iwn_url_encoded_aws_len(const char *src, ssize_t src_len);

IW_EXPORT size_t iwn_url_encode_aws(const char *src, ssize_t src_len, char *out, size_t out_size);

/// Decodes `%XX` escapes in place. Malformed escapes are left as is.
/// The `+` character is converted to a space.
IW_EXPORT void iwn_url_decode_inplace(char *str);

/// Decodes `%XX` escapes in place. Malformed escapes are left as is.
/// Unlike `iwn_url_decode_inplace()` the `+` character is not treated as a space,
/// because it has no special meaning inside an URI path (RFC 3986).
IW_EXPORT void iwn_url_decode_path_inplace(char *str);

IW_EXPORT size_t iwn_url_decode_inplace2(char *sp, char *ep);

IW_EXPORT size_t iwn_unescape_backslashes_inplace(char *str, ssize_t str_len);

IW_EXPORT IW_ALLOC char* iwn_url_encode_printf_va(const char *fmt, va_list va);

IW_EXPORT IW_ALLOC char* iwn_url_encode_new_printf(const char *fmt, ...) __attribute__((format(__printf__, 1, 2)));

IW_EXTERN_C_END;

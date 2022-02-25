#pragma once

#include <iowow/basedefs.h>

IW_EXTERN_C_START

IW_EXPORT const char* iwn_mimetype_find(const char *ext);

IW_EXPORT const char* iwn_mimetype_find_by_path(const char *path);

IW_EXPORT const char* iwn_mimetype_find_by_path2(const char *path, size_t path_len);

IW_EXTERN_C_END

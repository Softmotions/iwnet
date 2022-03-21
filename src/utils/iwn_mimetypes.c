#include "iwn_mimetypes.h"
#include "generated_mimegen.h"

#include <limits.h>

const char* iwn_mimetype_find(const char *ext) {
  return _mimetype_find(ext);
}

const char* iwn_mimetype_find_by_path2(const char *path, size_t len) {
  if (len < 2 || path[len - 1] == '.' || len > PATH_MAX) {
    return 0;
  }
  for (int i = (int) len - 2; i >= 0; --i) {
    if (path[i] == '.') {
      char buf[len - i];
      memcpy(buf, path + i + 1, len - i - 1);
      buf[len - i - 1] = '\0';
      return _mimetype_find(buf);
    }
  }
  return 0;
}

const char* iwn_mimetype_find_by_path(const char *path) {
  return iwn_mimetype_find_by_path2(path, strlen(path));
}

#include "iwn_mimetypes.h"
#include "generated_mimegen.h"

const char* iwn_mimetype_find(const char *ext) {
  return _mimetype_find(ext);
}

const char* iwn_mimetype_find_by_path2(const char *path, size_t len) {
  if (len < 2 || path[len - 1] == '.') {
    return 0;
  }
  for (int i = (int) len - 2; i >= 0; --i) {
    if (path[i] == '.') {
      return _mimetype_find(path + i + 1);
    }
  }
  return 0;
}

const char* iwn_mimetype_find_by_path(const char *path) {
  return iwn_mimetype_find_by_path2(path, strlen(path));
}

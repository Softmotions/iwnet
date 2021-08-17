#include "codec.h"

IW_INLINE bool is_anum(char c) {
  return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

size_t url_component_size(const char *src, size_t src_len) {
  size_t res = 0;
  for (int i = 0; i < src_len; ++i) {
    if (is_anum(src[i])) {
      res++;
    } else {
      res += 3;
    }
  }
  return res;
}

void url_component_encode(const char *src, size_t src_len, char *tgt, size_t tgt_len) {
}

IW_ALLOC char* url_component_encode_new(const char *src, size_t src_len) {
  return 0;
}

void url_component_decode_inplace(char *buf) {
}

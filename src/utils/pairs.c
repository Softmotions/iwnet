#include "pairs.h"

#include <string.h>

void iwn_pair_add(struct iwn_pairs *pairs, struct iwn_pair *p) {
  p->next = 0;
  if (pairs->last) {
    pairs->last->next = p;
    pairs->last = p;
  } else {
    pairs->first = pairs->last = p;
    return;
  }
}

struct iwn_pair* iwn_pair_find(struct iwn_pairs *pairs, const char *key, ssize_t key_len) {
  if (key_len < 0) {
    key_len = strlen(key);
  }
  for (struct iwn_pair *p = pairs->first; p; p = p->next) {
    if (p->key_len == key_len && strncmp(p->key, key, key_len) == 0) {
      return p;
    }
  }
  return 0;
}

void iwn_pair_add_pool(
  IWPOOL           *pool,
  struct iwn_pairs *pairs,
  const char       *key,
  ssize_t           key_len,
  char             *val,
  ssize_t           val_len
  ) {
  struct iwn_pair *p = iwpool_alloc(sizeof(*p), pool);
  if (p) {
    if (key_len < 0) {
      key_len = strlen(key);
    }
    if (val_len < 0) {
      val_len = strlen(val);
    }
    p->key = key;
    p->key_len = key_len;
    p->val = val;
    p->val_len = 0;
    iwn_pair_add(pairs, p);
  }
}

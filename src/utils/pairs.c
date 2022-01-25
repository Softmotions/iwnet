#include "pairs.h"

#include <iowow/iwlog.h>

#include <errno.h>
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
  if (IW_UNLIKELY(!pairs || !key || !key_len)) {
    return 0;
  }
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

struct iwn_val iwn_pair_find_val(struct iwn_pairs *pairs, const char *key, ssize_t key_len) {
  struct iwn_pair *p = iwn_pair_find(pairs, key, key_len);
  if (p) {
    return (struct iwn_val) {
             .buf = p->val,
             .len = p->val_len
    };
  }
  return (struct iwn_val) {};
}

iwrc iwn_pair_add_pool(
  IWPOOL           *pool,
  struct iwn_pairs *pairs,
  const char       *key,
  ssize_t           key_len,
  char             *val,
  ssize_t           val_len
  ) {
  struct iwn_pair *p = iwpool_alloc(sizeof(*p), pool);
  if (!p) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  if (key_len < 0) {
    key_len = strlen(key);
  }
  if (val_len < 0) {
    val_len = strlen(val);
  }
  p->key = key;
  p->key_len = key_len;
  p->val = val;
  p->val_len = val_len;
  iwn_pair_add(pairs, p);
  return 0;
}

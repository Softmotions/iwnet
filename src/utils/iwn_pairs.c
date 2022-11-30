#include "iwn_pairs.h"

#include <iowow/iwlog.h>

#include <errno.h>
#include <string.h>
#include <stdlib.h>

void iwn_val_buf_free(struct iwn_val *val) {
  if (val) {
    free(val->buf);
    val->buf = 0;
  }
}

void iwn_val_add(struct iwn_vals *vals, struct iwn_val *v) {
  v->next = 0;
  if (vals->last) {
    vals->last->next = v;
    vals->last = v;
  } else {
    vals->first = vals->last = v;
  }
}

iwrc iwn_val_add_new(struct iwn_vals *vals, char *buf, size_t len) {
  struct iwn_val *v = malloc(sizeof(*v));
  if (!v) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  v->buf = buf;
  v->len = len;
  iwn_val_add(vals, v);
  return 0;
}

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

iwrc iwn_pair_add_pool_all(
  IWPOOL           *pool,
  struct iwn_pairs *pairs,
  const char       *key,
  ssize_t           key_len,
  const char       *val,
  ssize_t           val_len
  ) {
  char *pval = 0;
  if (val_len) {
    if (val_len < 0) {
      val_len = strlen(val);
    }
    pval = iwpool_strndup2(pool, val, val_len);
    if (!pval) {
      return iwrc_set_errno(IW_ERROR_ALLOC, errno);
    }
  }
  if (key_len < 0) {
    key_len = strlen(key);
  }
  key = iwpool_strndup2(pool, key, key_len);
  if (!key) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  return iwn_pair_add_pool(pool, pairs, key, key_len, pval, val_len);
}

struct iwn_pair** iwn_pairs_to_array(IWPOOL *pool, const struct iwn_pairs *pairs, size_t *out_size) {
  size_t cnt = 0;
  for (struct iwn_pair *p = pairs->first; p; p = p->next) {
    ++cnt;
  }
  // NOLINTNEXTLINE
  struct iwn_pair **ret = iwpool_alloc(sizeof(*ret) * cnt, pool);
  if (ret) {
    *out_size = cnt;
    cnt = 0;
    for (struct iwn_pair *p = pairs->first; p; p = p->next) {
      ret[cnt++] = p;
    }
  }
  return ret;
}

struct iwn_val** iwn_vals_to_array(IWPOOL *pool, const struct iwn_vals *vals, size_t *out_size) {
  size_t cnt = 0;
  for (struct iwn_val *v = vals->first; v; v = v->next) {
    ++cnt;
  }
  // NOLINTNEXTLINE
  struct iwn_val **ret = iwpool_alloc(sizeof(*ret) * cnt, pool);
  if (ret) {
    *out_size = cnt;
    cnt = 0;
    for (struct iwn_val *v = vals->first; v; v = v->next) {
      ret[cnt++] = v;
    }
  }
  return ret;
}

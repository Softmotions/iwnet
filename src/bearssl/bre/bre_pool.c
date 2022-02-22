#include "bre_pool.h"

#define POOL_UNIT_ALIGN_SIZE 8

#ifndef SIZE_T_MAX
#define SIZE_T_MAX ((size_t) -1)
#endif

#define ROUNDUP(x_, v_) (((x_) + (v_) - 1) & ~((v_) - 1))

struct pool *pool_create(bre_alloc alloc, bre_dealloc dealloc, size_t siz) {
  struct pool *pool;
  siz = siz < 1 ? 32 : siz;
  siz = ROUNDUP(siz, POOL_UNIT_ALIGN_SIZE);
  pool = alloc(sizeof(*pool));
  if (!pool) {
    goto error;
  }
  pool->unit = alloc(sizeof(*pool->unit));
  if (!pool->unit) {
    goto error;
  }
  pool->unit->heap = alloc(siz);
  if (!pool->unit->heap) {
    goto error;
  }
  pool->asiz = siz;
  pool->heap = pool->unit->heap;
  pool->usiz = 0;
  pool->unit->next = 0;
  pool->user_data = 0;
  pool->user_data_free_fn = 0;
  pool->alloc = alloc;
  pool->dealloc = dealloc;
  return pool;

error:
  if (pool) {
    if (pool->unit && pool->unit->heap) {
      dealloc(pool->unit->heap);
    }
    dealloc(pool->unit);
    dealloc(pool);
  }
  return 0;
}

void pool_destroy(struct pool *pool) {
  if (!pool) {
    return;
  }

  for (struct pool_unit *u = pool->unit, *next; u; u = next) {
    next = u->next;
    pool->dealloc(u->heap);
    pool->dealloc(u);
  }
  if (pool->user_data_free_fn) {
    pool->user_data_free_fn(pool->user_data);
  }
  pool->dealloc(pool);
}

static int pool_extend(struct pool *pool, size_t siz) {
  struct pool_unit *nunit = pool->alloc(sizeof(*nunit));
  if (!nunit) {
    return 0;
  }
  siz = ROUNDUP(siz, POOL_UNIT_ALIGN_SIZE);
  nunit->heap = pool->alloc(siz);
  if (!nunit->heap) {
    pool->dealloc(nunit);
    return 0;
  }
  nunit->next = pool->unit;
  pool->heap = nunit->heap;
  pool->unit = nunit;
  pool->usiz = 0;
  pool->asiz = siz;
  return 1;
}

void *pool_alloc(size_t siz, struct pool *pool) {
  siz = ROUNDUP(siz, POOL_UNIT_ALIGN_SIZE);
  size_t usiz = pool->usiz + siz;
  if (SIZE_T_MAX - pool->usiz < siz) {
    return 0;
  }
  void *h = pool->heap;
  if (usiz > pool->asiz) {
    if (SIZE_T_MAX - pool->asiz < usiz) {
      return 0;
    }
    usiz = usiz + pool->asiz;
    if (!pool_extend(pool, usiz)) {
      return 0;
    }
    h = pool->heap;
  }
  pool->usiz += siz;
  pool->heap += siz;
  return h;
}

void *pool_calloc(size_t siz, struct pool *pool) {
  void *res = pool_alloc(siz, pool);
  if (!res) {
    return 0;
  }
  memset(res, 0, siz);
  return res;
}

char *pool_strndup(struct pool *pool, const char *str, size_t len) {
  char *ret = pool_alloc(len + 1, pool);
  if (!ret) {
    return 0;
  }
  memcpy(ret, str, len);
  ret[len] = '\0';
  return ret;
}

char *pool_strdup(struct pool *pool, const char *str) {
  return pool_strndup(pool, str, strlen(str));
}

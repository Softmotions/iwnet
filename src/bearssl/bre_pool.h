#pragma once

#include "bre_base.h"

struct pool_unit {
  void *heap;
  struct pool_unit *next;
};

/** Memory pool */
struct pool {
  size_t usiz;                           /**< Used size */
  size_t asiz;                           /**< Allocated size */
  char   *heap;                          /**< Current pool heap ptr */
  struct pool_unit *unit;                /**< Current heap unit */
  void      *user_data;                  /**< Associated user data */
  void      (*user_data_free_fn)(void*); /**< User data dispose function */
  bre_alloc alloc;
  bre_dealloc dealloc;
};

struct pool *pool_create(bre_alloc alloc, bre_dealloc dealloc, size_t siz);

void pool_destroy(struct pool *pool);

void *pool_alloc(size_t siz, struct pool *pool);

void *pool_calloc(size_t siz, struct pool *pool);

char *pool_strndup(struct pool *pool, const char *str, size_t len);

char *pool_strdup(struct pool *pool, const char *str);

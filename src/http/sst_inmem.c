#include "sst_inmem.h"

#include <iowow/iwlog.h>
#include <iowow/iwhmap.h>

#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <errno.h>

struct impl {
  IWHMAP *sidmap;
  pthread_mutex_t mtx;
};

static void _map_kv_free(void *key, void *val) {
  free(key);
  free(val);
}

static void _sidmap_kv_free(void *key, void *val) {
  free(key);
  IWHMAP *map = val;
  iwhmap_destroy(map);
}

static void _dispose(struct iwn_wf_session_store *sst) {
  struct impl *impl = sst->user_data;
  if (impl) {
    sst->user_data = 0;
    iwhmap_destroy(impl->sidmap);
    pthread_mutex_destroy(&impl->mtx);
    free(impl);
  }
}

static iwrc _put(struct iwn_wf_session_store *sst, const char *sid_, const char *key_, const char *val_) {
  iwrc rc = 0;
  char *sid = 0, *key = 0, *val = 0;
  struct impl *impl = sst->user_data;

  pthread_mutex_lock(&impl->mtx);

  IWHMAP *map = iwhmap_get(impl->sidmap, sid_);
  if (!map) {
    RCA(map = iwhmap_create_str(_map_kv_free), finish);
    RCA(sid = strdup(sid_), finish);
    RCC(rc, finish, iwhmap_put(impl->sidmap, sid, map));
    sid = 0; // avoid double free if error below
  }

  RCA(key = strdup(key_), finish);
  RCA(val = strdup(val_), finish);
  rc = iwhmap_put(map, key, val);

finish:
  pthread_mutex_unlock(&impl->mtx);
  if (rc) {
    free(sid);
    free(key);
    free(val);
  }
  return rc;
}

static void _del(struct iwn_wf_session_store *sst, const char *sid, const char *key) {
  struct impl *impl = sst->user_data;
  pthread_mutex_lock(&impl->mtx);
  IWHMAP *map = iwhmap_get(impl->sidmap, sid);
  if (map) {
    iwhmap_remove(map, key);
    if (iwhmap_count(map) == 0) {
      iwhmap_remove(impl->sidmap, sid);
    }
  }
  pthread_mutex_unlock(&impl->mtx);
}

IW_ALLOC static char* _get(struct iwn_wf_session_store *sst, const char *sid, const char *key) {
  char *ret = 0;
  struct impl *impl = sst->user_data;
  pthread_mutex_lock(&impl->mtx);
  IWHMAP *map = iwhmap_get(impl->sidmap, sid);
  if (map) {
    ret = iwhmap_get(map, key);
    if (ret) {
      ret = strdup(ret);
    }
  }
  pthread_mutex_unlock(&impl->mtx);
  return ret;
}

static void _clear(struct iwn_wf_session_store *sst, const char *sid) {
  struct impl *impl = sst->user_data;
  pthread_mutex_lock(&impl->mtx);
  IWHMAP *map = iwhmap_get(impl->sidmap, sid);
  if (map) {
    iwhmap_remove(map, sid);
  }
  pthread_mutex_unlock(&impl->mtx);
}

iwrc sst_inmem_create(struct iwn_wf_session_store *sst) {
  iwrc rc = 0;
  struct impl *impl;

  memset(sst, 0, sizeof(*sst));
  RCA(impl = calloc(1, sizeof(*impl)), finish);
  sst->user_data = impl;
  sst->put = _put;
  sst->del = _del;
  sst->get = _get;
  sst->clear = _clear;
  sst->dispose = _dispose;
  memcpy(&impl->mtx, &(pthread_mutex_t) PTHREAD_MUTEX_INITIALIZER, sizeof(impl->mtx));
  RCA(impl->sidmap = iwhmap_create_str(_sidmap_kv_free), finish);

finish:
  if (rc) {
    _dispose(sst);
  }
  return rc;
}

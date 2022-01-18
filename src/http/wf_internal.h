#pragma once

#include "wf.h"

#include <iowow/iwre.h>
#include <iowow/iwpool.h>
#include <iowow/iwlog.h>

struct route;

struct pair {
  const char *key;
  char       *val;
  size_t      key_len;
  size_t      val_len;
  struct pair *next;
};

struct pairs {
  struct pair *first;
  struct pair *last;
};

struct ctx {
  struct iwn_wf_ctx  base;
  struct route      *root;
  struct iwn_poller *poller;
  IWPOOL *pool;
  int     server_fd;
  int     request_file_max_size;
};

struct route {
  struct iwn_wf_route base;
  struct route       *parent;
  struct route       *child;
  struct route       *next;
  pthread_mutex_t     mtx;
  char      *pattern;
  struct re *pattern_re;
  int      pattern_len;
  uint32_t flags;
};

#define ROUTE_MATCHING_STACK_SIZE 127

struct route_iter {
  struct request *req;
  int cnt; ///< Position of top element on stack
  int prev_sibling_mlen;
  struct route *stack[ROUTE_MATCHING_STACK_SIZE];
  int mlen[ROUTE_MATCHING_STACK_SIZE];  // Matched sections lengh
};

struct request {
  struct iwn_wf_req base;
  struct pairs      query_params;
  struct pairs      post_params;
  struct route_iter it; ///< Routes matching iterator
  IWPOOL *pool;
};

#ifdef IW_TESTS

void dbg_request_destroy(struct request *req);
void dbg_route_iter_init(struct request *req, struct route_iter *it);
struct route* dbg_route_iter_next(struct route_iter *it);

#endif

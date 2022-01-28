#pragma once

#include "wf.h"
#include "http_server_internal.h"

#include <iowow/iwre.h>
#include <iowow/iwpool.h>
#include <iowow/iwlog.h>

#include <stdio.h>

struct route;

struct ctx {
  struct iwn_wf_ctx base;
  struct iwn_wf_session_store sst;
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
  int pattern_len;
};

#define ROUTE_MATCHING_STACK_SIZE 127

struct route_iter {
  struct request *req;
  int cnt; ///< Position of top element on stack
  int prev_sibling_mlen;
  struct route *stack[ROUTE_MATCHING_STACK_SIZE];
  int mlen[ROUTE_MATCHING_STACK_SIZE];  // Matched sections lengh
};

#define REQUEST_STREAM_FILE_MMAPED 0x01U

struct request {
  struct iwn_wf_req base;
  struct route_iter it; ///< Routes matching iterator
  IWPOOL     *pool;
  FILE       *stream_file;
  const char *boundary; ///< Current multipart form boundary
  const char *stream_file_path;
  size_t      streamed_bytes;
  size_t      path_len;
  size_t      boundary_len;
  char    sid[IWN_WF_SESSION_ID_LEN + 1];    //< Session id
  uint8_t flags;
};

#ifdef IW_TESTS

void dbg_request_destroy(struct request *req);
void dbg_route_iter_init(struct request *req, struct route_iter *it);
struct route* dbg_route_iter_next(struct route_iter *it);
const char* dbg_multipart_parse_next(
  IWPOOL           *pool,
  const char       *boundary,
  size_t            boundary_len,
  const char       *rp,
  const char* const ep,
  struct iwn_pairs *bp,
  bool             *eof);

#endif

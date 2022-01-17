#include "wf_internal.h"
#include "utils/codec.h"

#include <assert.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <stdbool.h>
#include <pthread.h>

static const char* _ecodefn(locale_t, uint32_t);

IW_INLINE iwrc _init(void) {
  static bool _initialized;
  if (__sync_bool_compare_and_swap(&_initialized, false, true)) {
    RCR(iwlog_register_ecodefn(_ecodefn));
  }
  return 0;
}

IW_INLINE void _pair_add(struct pairs *pairs, struct pair *p) {
  p->next = 0;
  if (pairs->last) {
    pairs->last->next = p;
    pairs->last = p;
  } else {
    pairs->first = pairs->last = p;
    return;
  }
}

struct pair* _pair_find(struct pairs *pairs, const char *key, ssize_t key_len) {
  if (key_len < 0) {
    key_len = strlen(key);
  }
  for (struct pair *p = pairs->first; p; p = p->next) {
    if (p->key_len == key_len && strncmp(p->key, key, key_len) == 0) {
      return p;
    }
  }
  return 0;
}

static void _pair_add2(
  IWPOOL       *pool,
  struct pairs *pairs,
  const char   *key,
  ssize_t       key_len,
  char         *val,
  ssize_t       val_len
  ) {
  struct pair *p = iwpool_alloc(sizeof(*p), pool);
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
    _pair_add(pairs, p);
  }
}

IW_INLINE iwrc _iwre_code(int mret) {
  switch (mret) {
    case RE_ERROR_NOMEM:
      return IW_ERROR_ALLOC;
    case RE_ERROR_CHARSET:
      return WF_ERROR_REGEXP_CHARSET;
    case RE_ERROR_SUBEXP:
      return WF_ERROR_REGEXP_SUBEXP;
    case RE_ERROR_SUBMATCH:
      return WF_ERROR_REGEXP_SUBMATCH;
    case RE_ERROR_ENGINE:
      return WF_ERROR_REGEXP_ENGINE;
  }
  return 0;
}

static void _route_destroy(struct route *route) {
  struct iwn_wf_route *base = &route->base;
  iwn_wf_handler_dispose handler_dispose = base->handler_dispose;
  if (handler_dispose) {
    base->handler_dispose = 0;
    handler_dispose(base->ctx, base->user_data);
  }
  route->pattern = 0;
  route->pattern_len = 0;
  if (route->pattern_re) {
    iwre_free(route->pattern_re);
    route->pattern_re = 0;
  }
  pthread_mutex_destroy(&route->mtx);
}

static void _route_destroy_deep(struct route *route) {
  for (struct route *r = route->child, *n = 0; r; r = n) {
    n = r->next;
    _route_destroy(r);
  }
  _route_destroy(route);
}

static void _ctx_destroy(struct ctx *ctx) {
  if (!ctx) {
    return;
  }
  if (ctx->root) {
    _route_destroy_deep(ctx->root);
  }
  iwpool_destroy(ctx->pool);
}

static void _on_server_dispose(const struct iwn_http_server *server) {
  struct ctx *ctx = server->user_data;
  if (ctx) {
    _ctx_destroy(ctx);
  }
}

static void _route_attach(struct route *parent, struct route *route) {
  route->next = route->child = 0;
  route->parent = parent;
  struct route *r = parent->child;
  if (r) {
    do {
      if (!r->next) {
        r->next = route;
        break;
      }
    } while ((r = r->next));
  } else {
    parent->child = route;
  }
}

static iwrc _route_init(struct route *route) {
  iwrc rc = 0;
  struct iwn_wf_route *base = &route->base;
  char *pattern = route->pattern;
  size_t len = pattern ? strlen(pattern) : 0;
  route->pattern_len = len;
  if (len) {
    if (*pattern == '^') { // We use regexp
      if (pattern[len - 1] == '$') {
        route->flags |= IWN_WF_FLAG_MATCH_END;
        pattern[len - 1] = '\0';
      }
      route->pattern++; // skip `^`
      RCA(route->pattern_re = iwre_new(route->pattern), finish);
      // Check pattern matching
      rc = _iwre_code(iwre_match(route->pattern_re, ""));
    }
  } else {
    route->pattern = 0;
  }

finish:
  return rc;
}

static iwrc _route_import(const struct iwn_wf_route *spec, struct ctx *ctx, struct route **out) {
  *out = 0;
  iwrc rc = 0;
  int n = 0;
  struct route *route;
  struct iwn_wf_route *base;
  IWPOOL *pool = ctx->pool;

  if (spec->parent) {
    for (struct route *r = (void*) spec->parent; r; r = r->parent) {
      ++n;
    }
    if (n >= ROUTE_MATCHING_STACK_SIZE - 1) {
      return WF_ERROR_MAX_NESTED_ROUTES;
    }
  }

  if (spec->parent && spec->parent->ctx != &ctx->base) {
    return WF_ERROR_PARENT_ROUTE_FROM_DIFFERENT_CONTEXT;
  }

  RCA(route = iwpool_calloc(sizeof(*route), pool), finish);
  memcpy(&route->mtx, &(pthread_mutex_t) PTHREAD_MUTEX_INITIALIZER, sizeof(route->mtx));
  memcpy(&route->base, spec, sizeof(route->base));
  base = &route->base;
  if (!(base->flags & IWN_WF_ALL_METHODS)) {
    base->flags |= IWN_WF_GET;
  }
  route->flags = base->flags;
  if (base->parent) {
    route->parent = (void*) route->base.parent;
  }
  if (spec->pattern) {
    RCA(base->pattern = iwpool_strdup2(pool, spec->pattern), finish);
    route->pattern = (char*) base->pattern; // Discarding `const` here
  }
  if (spec->tag) {
    RCA(base->tag = iwpool_strdup2(pool, spec->tag), finish);
  }
  RCR(_route_init(route));
  if (!route->parent && ctx->root) {
    base->parent = &ctx->root->base;
    route->parent = ctx->root;
  }
  if (route->parent) {
    _route_attach(route->parent, route);
  } else {
    ctx->root = route;
  }
  *out = route;

finish:
  if (rc) {
    if (route) {
      _route_destroy(route);
    }
  }
  return rc;
}

static void _request_destroy(struct request *req) {
  if (req) {
    if (req->base.request_dispose) {
      req->base.request_dispose(&req->base);
    }
    if (req->pool) {
      iwpool_destroy(req->pool);
    }
  }
}

static void _request_on_destroy(struct iwn_http_request *hreq) {
  struct request *req = hreq->request_user_data;
  if (req) {
    hreq->request_user_data = 0;
    _request_destroy(req);
  }
}

static iwrc _request_parse_query(struct request *req, char *p) {
  iwrc rc = 0;
  IWPOOL *pool = req->pool;
  char *key = 0, *val = 0;
  int state = 0;

  key = p;
  while (*p) {
    if (state == 0) {
      if (*p == '=') {
        *p = '\0';
        val = p + 1;
        state = 1;
      } else if (*p == '&') {
        *p = '\0';
        iwn_url_decode_inplace(p, -1);
        _pair_add2(pool, &req->query_params, key, -1, "", 0);
        key = p + 1;
        state = 0;
      }
    } else {
      if (*p == '&') {
        *p = '\0';
        iwn_url_decode_inplace(key, -1);
        iwn_url_decode_inplace(val, -1);
        _pair_add2(pool, &req->query_params, key, -1, val, -1);
        key = p + 1;
        state = 0;
      }
    }
    ++p;
  }
  if (state == 0) {
    if (key[0] != '\0') {
      iwn_url_decode_inplace(key, -1);
      _pair_add2(pool, &req->query_params, key, -1, "", 0);
    } else {
      iwn_url_decode_inplace(key, -1);
      iwn_url_decode_inplace(val, -1);
      _pair_add2(pool, &req->query_params, key, -1, val, -1);
    }
  }

  return rc;
}

static iwrc _request_parse_target(struct request *req) {
  iwrc rc = 0;
  char *p;
  size_t i;
  IWPOOL *pool = req->pool;

  struct iwn_http_val val = iwn_http_request_target(req->base.http);
  if (!val.len) {
    rc = IW_ERROR_ASSERTION;
    goto finish;
  }
  for (i = 0; i < val.len; ++i) {
    if (val.buf[i] == '?') {
      break;
    }
  }
  RCA(p = iwpool_strndup2(pool, val.buf, i), finish);
  iwn_url_decode_inplace(p, i);

  req->base.path_unmatched = req->base.path = p;
  if (++i < val.len) {
    char *q;
    RCA(q = iwpool_strndup2(pool, val.buf + i, val.len - i), finish);
    RCC(rc, finish, _request_parse_query(req, q));
  }

finish:
  return rc;
}

static iwrc _request_parse_method(struct request *req) {
  struct iwn_http_val val = iwn_http_request_method(req->base.http);
  if (!val.len) {
    return IW_ERROR_ASSERTION;
  }
  switch (val.len) {
    case 3:
      if (strncmp(val.buf, "GET", val.len) == 0) {
        req->base.method = IWN_WF_GET;
      } else if (strncmp(val.buf, "PUT", val.len) == 0) {
        req->base.method = IWN_WF_PUT;
      }
      break;
    case 4:
      if (strncmp(val.buf, "POST", val.len) == 0) {
        req->base.method = IWN_WF_POST;
      } else if (strncmp(val.buf, "HEAD", val.len) == 0) {
        req->base.method = IWN_WF_HEAD;
      }
      break;
    default:
      if (strncmp(val.buf, "DELETE", val.len) == 0) {
        req->base.method = IWN_WF_DELETE;
      } else if (strncmp(val.buf, "OPTIONS", val.len) == 0) {
        req->base.method = IWN_WF_OPTIONS;
      } else if (strncmp(val.buf, "PATCH", val.len) == 0) {
        req->base.method = IWN_WF_PATCH;
      } else {
        return WF_ERROR_UNSUPPORTED_HTTP_METHOD;
      }
  }
  return 0;
}

static bool _route_do_match(int pos, struct route_iter *it) {
  struct route *r = it->stack[pos];
  if (!r) {
    return false;
  }
  struct request *req = it->req;
  struct iwn_wf_req *wreq = &req->base;
  struct ctx *ctx = (void*) req->base.ctx;
  int mlen = 0;
  bool m = false;

  if (wreq->method & r->base.flags) { // Request method matched
    if (r->pattern_re) {              // RE
      // TODO:
    } else if (r->pattern) { // Simple path subpart match
      if (strncmp(wreq->path_unmatched, r->pattern, r->pattern_len) == 0) {
        mlen = r->pattern_len;
        m = true;
      }
    } else {
      m = true;
    }
    if (m) {
      const char *path_unmatched = wreq->path_unmatched += mlen - it->prev_sibling_mlen;
      if (*path_unmatched != '\0' && (r->flags & IWN_WF_FLAG_MATCH_END)) {
        m = false;
        mlen = 0;
      } else {
        wreq->path_unmatched = path_unmatched;
      }
    }
  }
  it->matched[pos] = m;
  it->mlen[pos] = mlen;
  if (m) {
    it->prev_sibling_mlen = mlen;
  }
  return m;
}

static void _route_iter_init(struct request *req, struct route_iter *iter) {
  req->base.path_unmatched = req->base.path;
  struct ctx *ctx = (void*) iter->req->base.ctx;
  memset(iter->stack, 0, sizeof(iter->stack));
  memset(iter->mlen, 0, sizeof(iter->mlen));
  memset(iter->matched, 0, sizeof(iter->matched));
  iter->stack[0] = ctx->root;
  iter->matched[0] = true;
  iter->prev_sibling_mlen = 0;
  iter->cnt = 1;
}

static struct route* _route_iter_pop_then_next(struct request *req, struct route_iter *it) {
  it->req->base.path_unmatched -= it->prev_sibling_mlen;
  if (--it->cnt > 0) {
    struct route *r = it->stack[it->cnt - 1];
    assert(r);
    it->prev_sibling_mlen = it->mlen[it->cnt - 1];
    r = it->stack[it->cnt - 1] = r->next;
    _route_do_match(it->cnt - 1, it);
    return r;
  } else {
    it->prev_sibling_mlen = 0;
  }
  return 0;
}

static struct route* _route_iter_next(struct request *req, struct route_iter *it) {
  while (it->cnt > 0) {
    bool m;
    struct route *r, *p = it->stack[it->cnt - 1];
    if (!p) {
      r = _route_iter_pop_then_next(req, it);
      m = r ? it->matched[it->cnt - 1] : 0;
    } else if (p->child && it->matched[it->cnt - 1]) {
      it->prev_sibling_mlen = 0;
      r = it->stack[it->cnt++] = p->child;
      m = _route_do_match(it->cnt - 1, it);
    } else {
      r = it->stack[it->cnt - 1] = p->next;
      m = _route_do_match(it->cnt - 1, it);
    }
    if (m && r->base.handler) {
      return r;
    }
  }
  return 0;
}

static iwrc _request_create(struct iwn_http_request *hreq) {
  iwrc rc = 0;
  struct request *req = 0;
  struct ctx *ctx = hreq->server_user_data;
  assert(ctx);
  IWPOOL *pool = iwpool_create_empty();
  if (!pool) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  RCA(req = iwpool_calloc(sizeof(*req), pool), finish);
  req->pool = pool;
  req->base.ctx = &ctx->base;
  req->base.http = hreq;

  RCC(rc, finish, _request_parse_target(req));
  RCC(rc, finish, _request_parse_method(req));

  // TODO:
  // req->first_matched_route = _request_first_mached_leaf_route(req, ctx->root);
  hreq->request_user_data = req;
  hreq->on_request_destroy = _request_on_destroy;

finish:
  if (rc) {
    if (req) {
      _request_destroy(req);
    } else {
      iwpool_destroy(pool);
    }
  }
  return rc;
}

static bool _request_process(struct request *req) {
  struct ctx *ctx = (void*) req->base.ctx;
  // TODO:
  return true;
}

static bool _request_stream_process(struct request *req) {
  struct ctx *ctx = (void*) req->base.ctx;
  if (ctx->request_file_max_size < 0) {
    return false;
  }
  // TODO:
  return false;
}

static bool _request_handler(struct iwn_http_request *hreq) {
  iwrc rc = 0;
  struct ctx *ctx = hreq->server_user_data;
  assert(ctx);
  struct request *req = hreq->request_user_data;
  if (!req) {
    RCC(rc, finish, _request_create(hreq));
  }
  // TODO:
  if (1) { //(!req->first_matched_route) {
    rc = iwn_http_response_write_code(hreq, 404);
    goto finish;
  }
  if (iwn_http_request_is_streamed(hreq)) {
    return _request_stream_process(req);
  } else {
    return _request_process(req);
  }

finish:
  if (rc) {
    iwlog_ecode_error3(rc);
    return false;
  }
  return true;
}

iwrc iwn_wf_route_create(const struct iwn_wf_route *spec, struct iwn_wf_route **out_route) {
  struct route *route;
  if (out_route) {
    *out_route = 0;
  }
  struct ctx *ctx = (void*) spec->ctx;
  if (!ctx && spec->parent) {
    ctx = (void*) spec->parent->ctx;
  }
  if (!ctx) {
    return IW_ERROR_INVALID_ARGS;
  }
  iwrc rc = _route_import(spec, ctx, &route);
  if (!rc && out_route) {
    *out_route = &route->base;
  }
  return rc;
}

iwrc iwn_wf_create(const struct iwn_wf_route *root_route_spec, struct iwn_wf_ctx **out_ctx) {
  if (!out_ctx) {
    return IW_ERROR_INVALID_ARGS;
  }
  *out_ctx = 0;
  if (!root_route_spec) {
    return IW_ERROR_INVALID_ARGS;
  }
  RCR(_init());
  IWPOOL *pool = iwpool_create_empty();
  if (!pool) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }

  iwrc rc = 0;
  struct ctx *ctx = 0;
  RCA(ctx = iwpool_calloc(sizeof(*ctx), pool), finish);
  ctx->pool = pool;
  RCC(rc, finish, _route_import(root_route_spec, ctx, &ctx->root));
  ctx->base.root = &ctx->root->base;

finish:
  if (rc) {
    if (ctx) {
      _ctx_destroy(ctx);
    } else {
      iwpool_destroy(pool);
    }
  } else {
    *out_ctx = &ctx->base;
  }
  return rc;
}

struct iwn_poller* iwn_wf_poller_get(struct iwn_wf_ctx *ctx) {
  return ((struct ctx*) ctx)->poller;
}

iwrc iwn_wf_server_create(const struct iwn_wf_server_spec *spec_, struct iwn_wf_ctx *ctx_) {
  struct ctx *ctx = (void*) ctx_;
  struct iwn_wf_server_spec spec;
  struct iwn_http_server_spec http = { 0 };

  memcpy(&spec, spec_, sizeof(spec));
  if (spec.request_file_max_size == 0) {
    spec.request_file_max_size = 50 * 1024 * 1024;
  }
  ctx->poller = spec.poller;
  ctx->request_file_max_size = spec.request_file_max_size;
  http.on_server_dispose = _on_server_dispose;
  http.request_handler = _request_handler;

  http.user_data = ctx;
  http.poller = spec.poller;
  http.listen = spec.listen;
  http.port = spec.port;
  http.certs = spec.certs;
  http.certs_in_buffer = spec.certs_in_buffer;
  http.certs_len = spec.certs_len;
  http.private_key = spec.private_key;
  http.private_key_in_buffer = spec.private_key_in_buffer;
  http.private_key_len = spec.private_key_len;
  http.socket_queue_size = spec.socket_queue_size;
  http.response_buf_size = spec.response_buf_size;
  http.request_buf_max_size = spec.request_buf_max_size;
  http.request_buf_size = spec.request_buf_size;
  http.request_timeout_keepalive_sec = spec.request_timeout_keepalive_sec;
  http.request_timeout_sec = spec.request_timeout_sec;
  http.request_token_max_len = spec.request_token_max_len;
  http.request_max_headers_count = spec.request_max_headers_count;

  return iwn_http_server_create(&http, &ctx->server_fd);
}

void iwn_wf_destroy(struct iwn_wf_ctx *ctx_) {
  struct ctx *ctx = (void*) ctx_;
  if (ctx->poller && ctx->server_fd > -1) {
    iwn_poller_remove(ctx->poller, ctx->server_fd);
  } else {
    _ctx_destroy(ctx);
  }
}

static const char* _ecodefn(locale_t locale, uint32_t ecode) {
  if (ecode <= _WF_ERROR_START || ecode >= _WF_ERROR_END) {
    return 0;
  }
  switch (ecode) {
    case WF_ERROR_INVALID_FORM_DATA:
      return "Invalid (unparseable) form data (WF_ERROR_INVALID_FORM_DATA)";
    case WF_ERROR_PARENT_ROUTE_FROM_DIFFERENT_CONTEXT:
      return "Parent router from different context (WF_ERROR_PARENT_ROUTER_FROM_DIFFERENT_CONTEXT)";
    case WF_ERROR_REGEXP_INVALID:
      return "Invalid regular expression (WF_ERROR_REGEXP_INVALID)";
    case WF_ERROR_REGEXP_CHARSET:
      return "Invalid regular expression: expected ']' at end of character set (WF_ERROR_REGEXP_CHARSET)";
    case WF_ERROR_REGEXP_SUBEXP:
      return "Invalid regular expression: expected ')' at end of subexpression (WF_ERROR_REGEXP_SUBEXP)";
    case WF_ERROR_REGEXP_SUBMATCH:
      return "Invalid regular expression: expected '}' at end of submatch (WF_ERROR_REGEXP_SUBMATCH)";
    case WF_ERROR_REGEXP_ENGINE:
      return "Illegal instruction in compiled regular expression (please report this bug) (WF_ERROR_REGEXP_ENGINE)";
    case WF_ERROR_UNSUPPORTED_HTTP_METHOD:
      return "Unsupported HTTP method (WF_ERROR_UNSUPPORTED_HTTP_METHOD)";
    case WF_ERROR_MAX_NESTED_ROUTES:
      return "Exceeds max number of nested routes: 127 (WF_ERROR_MAX_NESTED_ROUTES)";
  }
  return 0;
}

#ifdef IW_TESTS

void route_iter_init(struct request *req, struct route_iter *it) {
  _route_iter_init(req, it);
}

struct route* route_iter_next(struct request *req, struct route_iter *it) {
  return _route_iter_next(req, it);
}

void request_destroy(struct request *req) {
  _request_destroy(req);
}

#endif

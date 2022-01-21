#include "wf_internal.h"
#include "utils/codec.h"

#include <iowow/iwp.h>

#include <assert.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <stdbool.h>
#include <pthread.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/mman.h>

static int _aunit;

static const char* _ecodefn(locale_t, uint32_t);

IW_INLINE iwrc _init(void) {
  static bool _initialized;
  if (__sync_bool_compare_and_swap(&_initialized, false, true)) {
    RCR(iwlog_register_ecodefn(_ecodefn));
    _aunit = iwp_alloc_unit();
  }
  return 0;
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
  base->ctx = &ctx->base;
  if (!(base->flags & IWN_WF_METHODS_ALL)) {
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

static iwrc _request_parse_query_inplace(IWPOOL *pool, struct iwn_pairs *pairs, char *p, size_t len) {
  iwrc rc = 0;
  char *key = 0, *val = 0, *ep = p + len;
  int state = 0;

  key = p;
  while (p < ep) {
    if (state == 0) {
      if (*p == '=') {
        *p = '\0';
        val = p + 1;
        state = 1;
      } else if (*p == '&') {
        *p = '\0';
        iwn_url_decode_inplace(p, -1);
        RCC(rc, finish, iwn_pair_add_pool(pool, pairs, key, -1, "", 0));
        key = p + 1;
        state = 0;
      }
    } else {
      if (*p == '&') {
        *p = '\0';
        iwn_url_decode_inplace(key, -1);
        iwn_url_decode_inplace(val, -1);
        RCC(rc, finish, iwn_pair_add_pool(pool, pairs, key, -1, val, -1));
        key = p + 1;
        state = 0;
      }
    }
    ++p;
  }
  if (state == 0) {
    if (key[0] != '\0') {
      iwn_url_decode_inplace(key, -1);
      RCC(rc, finish, iwn_pair_add_pool(pool, pairs, key, -1, "", 0));
    }
  } else {
    iwn_url_decode_inplace(key, -1);
    iwn_url_decode_inplace(val, -1);
    RCC(rc, finish, iwn_pair_add_pool(pool, pairs, key, -1, val, -1));
  }

finish:
  return rc;
}

static void _request_stream_destroy(struct request *req) {
  if (req->stream_file) {
    if (req->flags & REQUEST_STREAM_FILE_MMAPED) {
      req->flags &= ~REQUEST_STREAM_FILE_MMAPED;
      munmap((void*) req->base.body, IW_ROUNDUP(req->base.body_len, _aunit));
    }
    fclose(req->stream_file);
    unlink(req->stream_file_path);
    req->stream_file = 0;
    req->stream_file_path = 0;
  }
}

static void _request_destroy(struct request *req) {
  if (req) {
    _request_stream_destroy(req);
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

static iwrc _request_parse_target(struct request *req) {
  iwrc rc = 0;
  char *p;
  size_t i;
  IWPOOL *pool = req->pool;

  struct iwn_val val = iwn_http_request_target(req->base.http);
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
    _request_parse_query_inplace(pool, &req->base.query_params, q, val.len - i);
  }

finish:
  return rc;
}

static iwrc _request_parse_method(struct request *req) {
  struct iwn_val val = iwn_http_request_method(req->base.http);
  if (!val.len) {
    return IW_ERROR_ASSERTION;
  }
  switch (val.len) {
    case 3:
      if (strncmp(val.buf, "GET", val.len) == 0) {
        req->base.flags = IWN_WF_GET;
      } else if (strncmp(val.buf, "PUT", val.len) == 0) {
        req->base.flags = IWN_WF_PUT;
      }
      break;
    case 4:
      if (strncmp(val.buf, "POST", val.len) == 0) {
        req->base.flags = IWN_WF_POST;
      } else if (strncmp(val.buf, "HEAD", val.len) == 0) {
        req->base.flags = IWN_WF_HEAD;
      }
      break;
    default:
      if (strncmp(val.buf, "DELETE", val.len) == 0) {
        req->base.flags = IWN_WF_DELETE;
      } else if (strncmp(val.buf, "OPTIONS", val.len) == 0) {
        req->base.flags = IWN_WF_OPTIONS;
      } else if (strncmp(val.buf, "PATCH", val.len) == 0) {
        req->base.flags = IWN_WF_PATCH;
      } else {
        return WF_ERROR_UNSUPPORTED_HTTP_METHOD;
      }
  }
  return 0;
}

IW_INLINE bool _c_is_ctl(char c) {
  return c >= 0 && c <= 31;
}

static bool _c_is_tspecial(char c) {
  switch (c) {
    case ';':
    case ',':
    case ':':
    case '=':
    case '?':
    case '/':
    case '\\':
    case '"':
    case '@':
    case '(':
    case ')':
    case '<':
    case '>':
    case '[':
    case ']':
      return true;
  }
  return false;
}

IW_INLINE bool _c_is_token(char c) {
  return !(c == ' ' || _c_is_ctl(c) || _c_is_tspecial(c));
}

IW_INLINE bool _c_is_space(char c) {
  return c == ' ' || c == '\t';
}

static char* _header_parse_next_parameter(char *rp, struct iwn_pair *kv) {
  memset(kv, 0, sizeof(*kv));
  for ( ; *rp && *rp != ';'; ++rp);
  if (*rp == '\0') {
    return 0;
  }
  bool quoted = false;
  char *ks = rp, *ke = ks;
  char *vs, *ve = 0;
  ++rp;
  while (*rp) {
    if (ks == ke) {
      if (_c_is_space(*rp)) { // skip leading space
        ks = ke = rp + 1;
      } else if (*rp == '=') {
        ke = rp;
        vs = rp + 1;
      } else if (!_c_is_token(*rp)) {
        return 0;
      }
      ++rp;
    } else {
      if (rp - 1 == ke && *rp == '"') {
        quoted = true;
        vs = ++rp;
      } else if (quoted) {
        if (*(rp - 1) == '\\') {
          ; // any char can be escaped
        } else if (*rp == '"') {
          ve = rp;
          break;
        } else if (*rp == '\r') {
          return 0;
        }
        ++rp;
      } else if (*rp == ';') {
        ve = rp;
        --rp;
        break;
      } else if (!_c_is_token(*rp)) {
        return 0;
      } else {
        ++rp;
        ve = rp;
      }
    }
  }
  if (ve) {
    kv->key = ks;
    kv->key_len = ke - ks;
    kv->val = vs;
    kv->val_len = ve - vs;
    return rp;
  } else {
    return 0;
  }
}

static iwrc _request_parse_headers(struct request *req) {
  iwrc rc = 0;
  struct iwn_val val = iwn_http_request_header_get(req->base.http, "content-type", sizeof("content-type") - 1);
  if (val.len > 0) {
    if (strncasecmp(val.buf, "application/x-www-form-urlencoded",
                    sizeof("application/x-www-form-urlencoded") - 1) == 0) {
      req->base.flags |= IWN_WF_FORM_URL_ENCODED;
    } else if (strncasecmp(val.buf, "multipart/form-data", sizeof("multipart/form-data") - 1) == 0) {
      req->base.flags |= IWN_WF_FORM_MULTIPART;
      char *rp = val.buf += sizeof("multipart/form-data") - 1;
      struct iwn_pair p;
      while ((rp = _header_parse_next_parameter(rp, &p))) {
        if (strncasecmp(p.key, "boundary", sizeof("boundary") - 1) == 0) {
          req->boundary = iwpool_strndup2(req->pool, p.val, p.val_len);
          break;
        }
      }
      if (!req->boundary) {
        return WF_ERROR_INVALID_FORM_DATA;
      }
    }
  }
  return rc;
}

static bool _route_do_match_next(int pos, struct route_iter *it) {
  struct route *r = it->stack[pos];
  struct request *req = it->req;
  struct iwn_wf_req *wreq = &req->base;
  const char *path_unmatched = wreq->path_unmatched - it->prev_sibling_mlen;
  struct ctx *ctx = (void*) req->base.ctx;
  int mlen = 0;

  if (!r) {
    wreq->path_unmatched = path_unmatched;
    it->prev_sibling_mlen = 0;
    return false;
  }

  if (wreq->flags & r->base.flags) { // Request method matched
    if (r->pattern_re) {             // RE
      pthread_mutex_lock(&r->mtx);
      int mret = iwre_match(r->pattern_re, path_unmatched);
      iwrc rc = _iwre_code(mret);
      if (IW_LIKELY(!rc)) {
        if (mret >= 0) {
          mlen = mret == 0 ? -1 : mret;
          for (int n = 0; n < r->pattern_re->nmatches; n += 2) { // Record regexp submatches
            struct route_re_submatch *sm = iwpool_alloc(sizeof(sm), req->pool);
            if (sm) {
              sm->route = &r->base;
              sm->input = path_unmatched;
              sm->sp = r->pattern_re->matches[n];
              sm->ep = r->pattern_re->matches[n + 1];
              if (wreq->last) {
                wreq->last->next = sm;
                wreq->last = sm;
              } else {
                wreq->first = wreq->last = sm;
              }
            }
          }
        }
      } else {
        iwlog_ecode_error(rc, "Route matching failed. Pattern: %s tag: %s", rc, r->pattern_re->expression,
                          (r->base.tag ? r->base.tag : ""));
      }
      pthread_mutex_unlock(&r->mtx);
    } else if (r->pattern) { // Simple path subpart match
      if (*path_unmatched && strncmp(path_unmatched, r->pattern, r->pattern_len) == 0) {
        mlen = r->pattern_len;
      }
    } else {
      // Matched the empty route
      mlen = -1;
    }
    if (mlen != 0) {
      if (mlen > 0) {
        path_unmatched += mlen;
      }
      if (*path_unmatched != '\0' && (r->flags & IWN_WF_FLAG_MATCH_END)) {
        mlen = 0;
      } else {
        wreq->path_unmatched = path_unmatched;
        it->prev_sibling_mlen = mlen > 0 ? mlen : 0;
      }
    }
  }

  it->mlen[pos] = mlen;
  return mlen != 0;
}

static void _route_iter_init(struct request *req, struct route_iter *it) {
  it->req = req;
  req->base.path_unmatched = req->base.path;
  struct ctx *ctx = (void*) it->req->base.ctx;
  memset(it->stack, 0, sizeof(it->stack));
  memset(it->mlen, 0, sizeof(it->mlen));
  it->stack[0] = ctx->root;
  it->mlen[0] = -1; // matched
  it->prev_sibling_mlen = 0;
  it->cnt = 1;
}

static struct route* _route_iter_pop_then_next(struct request *req, struct route_iter *it) {
  if (--it->cnt > 0) {
    struct route *r = it->stack[it->cnt - 1];
    it->prev_sibling_mlen = it->mlen[it->cnt - 1] > 0 ? it->mlen[it->cnt - 1] : 0;
    r = it->stack[it->cnt - 1] = r->next;
    _route_do_match_next(it->cnt - 1, it);
    return r;
  } else {
    it->prev_sibling_mlen = 0;
  }
  return 0;
}

static struct route* _route_iter_current(struct route_iter *it) {
  if (it->cnt > 0) {
    struct ctx *ctx = (void*) it->req->base.ctx;
    struct route *r = it->stack[it->cnt - 1];
    if (r && r != ctx->root && it->mlen[it->cnt - 1] != 0) {
      return r;
    }
  }
  return 0;
}

static struct route* _route_iter_next(struct route_iter *it) {
  struct request *req = it->req;
  while (it->cnt > 0) {
    bool m;
    struct route *r, *p = it->stack[it->cnt - 1];
    if (!p) {
      r = _route_iter_pop_then_next(req, it);
      m = r && it->mlen[it->cnt - 1] != 0;
    } else if (p->child && it->mlen[it->cnt - 1] != 0) {
      it->prev_sibling_mlen = 0;
      r = it->stack[it->cnt++] = p->child;
      m = _route_do_match_next(it->cnt - 1, it);
    } else {
      r = it->stack[it->cnt - 1] = p->next;
      m = _route_do_match_next(it->cnt - 1, it);
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
  RCC(rc, finish, _request_parse_headers(req));

  // Scroll to the first matched route
  _route_iter_init(req, &req->it);
  _route_iter_next(&req->it);

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

static bool _request_form_multipart_parse(struct request *req) {
  // TODO:
  return true;
}

IW_INLINE bool _request_form_url_encoded_parse(struct request *req) {
  if (  req->base.body_len > 0
     && !_request_parse_query_inplace(req->pool, &req->base.post_params, (char*) req->base.body, req->base.body_len)) {
    return false;
  }
  return true;
}

IW_INLINE bool _request_form_parse(struct request *req) {
  if (req->base.flags & IWN_WF_FORM_URL_ENCODED) {
    return _request_form_url_encoded_parse(req);
  } else if (req->base.flags & IWN_WF_FORM_MULTIPART) {
    return _request_form_multipart_parse(req);
  } else {
    return true;
  }
}

static bool _request_routes_process(struct request *req) {
  if (!_request_form_parse(req)) {
    return false;
  }
  int rv = 0;
  bool ok = true;

  for (struct route *r = _route_iter_current(&req->it); r; r = _route_iter_next(&req->it)) {
    if (r->base.handler) {
      rv = r->base.handler(&req->base, r->base.user_data);
      if (rv > 0) {
        if (rv > 1) {
          ok = iwn_http_response_by_code(req->base.http, rv);
        }
        break;
      } else if (rv < 0) {
        return false;
      }
    }
  }

  if (ok && rv == 0) { // Delegate all unhandled requests to the root route
    struct ctx *ctx = (void*) req->base.ctx;
    if (ctx->root->base.handler) {
      rv = ctx->root->base.handler(&req->base, ctx->root->base.user_data);
      if (rv > 1) {
        ok = iwn_http_response_by_code(req->base.http, rv);
      } else if (rv < 0) {
        ok = false;
      }
    }
    if (rv == 0) {
      // Respond with not found at least
      ok = iwn_http_response_by_code(req->base.http, 404);
    }
  }
  return ok;
}

static bool _request_process(struct request *req) {
  struct iwn_val val = iwn_http_request_body(req->base.http);
  req->base.body_len = val.len;
  req->base.body = val.len ? val.buf : 0;
  return _request_routes_process(req);
}

static bool _request_stream_process(struct request *req) {
  iwrc rc = 0;
  struct iwn_http_request *hreq = req->base.http;
  struct ctx *ctx = (void*) req->base.ctx;
  if (ctx->request_file_max_size < 0) {
    iwlog_warn("HTTP streaed requests are not allowed");
    return false;
  }
  struct iwn_val val = iwn_http_request_chunk_get(hreq);
  if (val.len > 0) {
    if (req->streamed_bytes + val.len > ctx->request_file_max_size) {
      _request_stream_destroy(req);
      iwlog_warn("HTTP streamed data size: %zu exceeds the maximum allowed size: %d",
                 (req->streamed_bytes + val.len), ctx->request_file_max_size);
      return false;
    }
    if (!req->stream_file) {
      char *fname;
      RCA(fname = iwp_allocate_tmpfile_path("iwn-wf-stream-"), finish);
      RCA(req->stream_file_path = iwpool_strdup2(req->pool, fname), finish);
      free(fname);
      req->stream_file = fopen(req->stream_file_path, "w+");
      if (!req->stream_file) {
        rc = iwrc_set_errno(IW_ERROR_IO_ERRNO, errno);
        goto finish;
      }
    }
    if (fwrite(val.buf, val.len, 1, req->stream_file) != 1) {
      rc = iwrc_set_errno(IW_ERROR_IO_ERRNO, errno);
      goto finish;
    }
    req->streamed_bytes += val.len;
  } else {
    if (req->streamed_bytes > 0) {
      int fd;
      RCN(finish, fflush(req->stream_file));
      RCN(finish, fd = fileno(req->stream_file));
      void *mm = mmap(0, IW_ROUNDUP(req->streamed_bytes, _aunit), PROT_READ, MAP_PRIVATE, fd, 0);
      if (!mm) {
        rc = iwrc_set_errno(IW_ERROR_ERRNO, errno);
        goto finish;
      }
      req->base.body = mm;
      req->base.body_len = req->streamed_bytes;
    }

    return _request_routes_process(req);
  }

finish:
  if (rc) {
    iwlog_ecode_error3(rc);
    return false;
  }
  return true;
}

static bool _request_handler(struct iwn_http_request *hreq) {
  struct ctx *ctx = hreq->server_user_data;
  assert(ctx);
  struct request *req = hreq->request_user_data;
  if (!req) {
    iwrc rc = _request_create(hreq);
    if (rc) {
      iwlog_ecode_error3(rc);
      return false;
    }
    req = hreq->request_user_data;
  }
  if (!_route_iter_current(&req->it)) {
    // No routes found.
    // Do not parse request body.
    // Call the root handler or respond 404
    req->base.flags &= ~IWN_WF_FORM_ALL;
    return _request_routes_process(req);
  } else if (iwn_http_request_is_streamed(hreq)) {
    return _request_stream_process(req);
  } else {
    return _request_process(req);
  }
}

iwrc iwn_wf_route(const struct iwn_wf_route *spec, struct iwn_wf_route **out_route) {
  struct route *route;
  if (out_route) {
    *out_route = 0;
  }
  struct ctx *ctx = (void*) spec->ctx;
  if (spec->parent) {
    if (spec->parent->flags & IWN_WF_FLAG_MATCH_END) {
      return WF_ERROR_ROUTE_CANNOT_BE_PARENT;
    }
    for (struct iwn_wf_route *p = spec->parent; !ctx && p; p = p->parent) {
      ctx = (void*) p->ctx;
    }
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

iwrc iwn_wf_server(const struct iwn_wf_server_spec *spec_, struct iwn_wf_ctx *ctx_) {
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
      return "Exceeds the maximum number of nested routes: 127 (WF_ERROR_MAX_NESTED_ROUTES)";
    case WF_ERROR_ROUTE_CANNOT_BE_PARENT:
      return "Route cannot be parent route (WF_ERROR_ROUTE_CANNOT_BE_PARENT)";
  }
  return 0;
}

#ifdef IW_TESTS

void dbg_route_iter_init(struct request *req, struct route_iter *it) {
  _route_iter_init(req, it);
}

struct route* dbg_route_iter_next(struct route_iter *it) {
  return _route_iter_next(it);
}

void dbg_request_destroy(struct request *req) {
  _request_destroy(req);
}

#endif

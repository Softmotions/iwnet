#include "iwn_wf_internal.h"
#include "iwn_wf_sst_inmem.h"
#include "iwn_codec.h"

#include <iowow/iowow.h>
#include <iowow/iwp.h>
#include <iowow/iwxstr.h>
#include <iowow/iwre.h>

#include <assert.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/mman.h>

static int _aunit;

static const char* _ecodefn(locale_t, uint32_t);
static void _response_headers_write(struct iwn_http_req *hreq);

IW_INLINE iwrc _init(void) {
  static bool _initialized;
  if (__sync_bool_compare_and_swap(&_initialized, false, true)) {
    RCR(iw_init());
    RCR(iwlog_register_ecodefn(_ecodefn));
    _aunit = iwp_alloc_unit();
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
    iwre_destroy(route->pattern_re);
    route->pattern_re = 0;
  }
  pthread_mutex_destroy(&route->mtx);
}

static void _route_destroy_deep(struct route *route) {
  for (struct route *r = route->child, *n = 0; r; r = n) {
    n = r->next;
    _route_destroy_deep(r);
  }
  _route_destroy(route);
}

static void _ctx_destroy(struct ctx *ctx) {
  if (!ctx) {
    return;
  }
  if (ctx->sst.dispose) {
    ctx->sst.dispose(&ctx->sst);
  }
  if (ctx->root) {
    _route_destroy_deep(ctx->root);
  }
  iwpool_destroy(ctx->pool);
}

static void _server_on_dispose(const struct iwn_http_server *server) {
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
  char *pattern = route->pattern;
  size_t len = pattern ? strlen(pattern) : 0;
  route->pattern_len = len;
  if (len) {
    if (*pattern == '^') { // We use regexp
      route->pattern++;    // skip `^`
      route->pattern_re = iwre_create(route->pattern);
      if (!route->pattern_re) {
        rc = WF_ERROR_REGEXP_INVALID;
        goto finish;
      }
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
  pthread_mutex_init(&route->mtx, 0);
  memcpy(&route->base, spec, sizeof(route->base));
  base = &route->base;
  base->ctx = &ctx->base;
  if (!(base->flags & IWN_WF_METHODS_ALL)) {
    base->flags |= IWN_WF_GET;
  }
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
  if (!p || !len) {
    return 0;
  }

  iwrc rc = 0;
  char *key = p, *val = 0, *ep = p + len;
  int state = 0;

  while (p < ep) {
    if (state == 0) {
      if (*p == '=') {
        *p = '\0';
        val = p + 1;
        state = 1;
      } else if (*p == '&') {
        *p = '\0';
        iwn_url_decode_inplace(key);
        RCC(rc, finish, iwn_pair_add_pool(pool, pairs, key, -1, "", 0));
        key = p + 1;
        state = 0;
      }
    } else {
      if (*p == '&') {
        *p = '\0';
        iwn_url_decode_inplace(key);
        iwn_url_decode_inplace(val);
        RCC(rc, finish, iwn_pair_add_pool(pool, pairs, key, -1, val, -1));
        key = p + 1;
        state = 0;
      }
    }
    ++p;
  }

  if (state == 0) {
    if (key[0] != '\0') {
      iwn_url_decode_inplace(key);
      RCC(rc, finish, iwn_pair_add_pool(pool, pairs, key, -1, "", 0));
    }
  } else {
    iwn_url_decode_inplace(key);
    iwn_url_decode_inplace(val);
    RCC(rc, finish, iwn_pair_add_pool(pool, pairs, key, -1, val, -1));
  }

finish:
  return rc;
}

static void _request_stream_destroy(struct request *req) {
  if (req->stream_file) {
    if (req->flags & REQUEST_STREAM_FILE_MMAPED) {
      req->flags &= ~REQUEST_STREAM_FILE_MMAPED;
      munmap((void*) req->base.body, IW_ROUNDUP(req->base.body_len + 1, _aunit));
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
    pthread_mutex_destroy(&req->sess_map_mtx);
    if (req->sess_map) {
      iwhmap_destroy(req->sess_map);
      req->sess_map = 0;
    }
    if (req->pool) {
      iwpool_destroy(req->pool);
    }
  }
}

static void _request_on_dispose(struct iwn_http_req *hreq) {
  struct request *req = iwn_http_request_wf_data(hreq);
  if (req) {
    _request_destroy(req);
  }
}

static iwrc _request_target_parse(struct request *req) {
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
  iwn_url_decode_inplace(p);

  req->base.path_unmatched = req->base.path = p;
  req->path_len = i;
  if (++i < val.len) {
    char *q;
    RCA(q = iwpool_strndup2(pool, val.buf + i, val.len - i), finish);
    _request_parse_query_inplace(pool, &req->base.query_params, q, val.len - i);
  }

finish:
  return rc;
}

static iwrc _request_method_parse(struct request *req) {
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

IW_INLINE bool _c_is_space(char c) {
  return c == ' ' || c == '\t';
}

bool _c_is_token(char c, bool is_value) {
  if (is_value && (_c_is_space(c) || c == ',')) {
    return true;
  }
  return !(_c_is_ctl(c) || _c_is_tspecial(c));
}

IW_INLINE bool _c_is_lsep(char c) {
  return c == '\r' || c == '\n';
}

static const char* _header_parse_skip_name(const char *rp, const char *ep) {
  const char *sp = rp;
  while (rp < ep) {
    if (*rp == ':') {
      if (rp > sp) {
        return rp;
      } else {
        return 0;
      }
    } else if (!_c_is_token(*rp, false)) {
      return 0;
    }
    ++rp;
  }
  return rp;
}

static const char* _header_parse_next_parameter2(
  bool header_value, const char *rp, const char *ep,
  struct iwn_pair *kv
  ) {
  if (rp >= ep || _c_is_lsep(*rp)) {
    return 0;
  }

  bool in_quote = false, in_key = true, expect_eq = false, val_escaped = false;
  const char *ks = rp, *ke = ks;
  const char *vs = 0, *ve = 0;

  while (rp < ep) {
    if (in_key) {
      if (header_value) {
        if (*rp == '=') {
          in_key = false;
          vs = ++rp;
        } else if (_c_is_space(*rp)) {
          if (ke == ks) {
            ke = ++ks;
          }
          ++rp;
        } else if (*rp == ';') {
          vs = ve = rp;
          ++rp;
          break;
        } else if (_c_is_lsep(*rp)) {
          vs = ve = rp;
          break;
        } else if ((*rp == '/' && ke != ks) || _c_is_token(*rp, false)) { // Allow '/' in header value
          ++rp;
          ke = rp;
        } else {
          return 0;
        }
      } else {
        if (*rp == '=') {
          in_key = false;
          vs = ++rp;
        } else if (_c_is_space(*rp)) {
          if (ke == ks) {
            ++ks;
            ke = ks;
          } else {
            expect_eq = true;
          }
          ++rp;
        } else if (!expect_eq && *rp == ';') {
          vs = ve = rp;
          ++rp;
          break;
        } else if (!expect_eq && _c_is_token(*rp, false)) {
          ++rp;
          ke = rp;
        } else {
          return 0;
        }
      }
    } else {
      if (IW_UNLIKELY(in_quote)) {
        if (*(rp - 1) == '\\') {
          val_escaped = true;
        } else if (*rp == '"') {
          ve = rp;
          ++rp;
          break;
        } else if (_c_is_lsep(*rp)) {
          return 0;
        }
        ++rp;
      } else if (*rp == '"' && vs == rp) {
        in_quote = true;
        vs = ++rp;
        ve = vs;
      } else if (*rp == ';' || _c_is_space(*rp)) {
        ve = rp;
        ++rp;
        break;
      } else if (_c_is_lsep(*rp)) {
        ve = rp;
        break;
      } else if (_c_is_token(*rp, true)) {
        ++rp;
        ve = rp;
      } else {
        return 0;
      }
    }
  }

  if (ve) {
    kv->key = ks;
    kv->key_len = ke - ks;
    kv->val = (char*) vs;
    kv->val_len = ve - vs;
    if (val_escaped) {
      kv->val_len = iwn_unescape_backslashes_inplace(kv->val, kv->val_len);
    }
    return rp;
  } else {
    return 0;
  }
}

static const char* _header_parse_next_parameter(const char *rp, const char *ep, struct iwn_pair *kv) {
  memset(kv, 0, sizeof(*kv));
  if (rp == 0) {
    return 0;
  }
  bool header_value = *rp == ':'; // Start if header value
  if (header_value) {
    ++rp;
  }
  return _header_parse_next_parameter2(header_value, rp, ep, kv);
}

const char* iwn_wf_header_val_part_next(
  const char *header_val, const char *ptr, const char *end,
  struct iwn_pair *out
  ) {
  return _header_parse_next_parameter2(ptr == header_val, ptr, end, out);
}

struct iwn_pair iwn_wf_header_val_part_find(const char *ptr, const char *end, const char *name) {
  struct iwn_pair kv;
  size_t nlen = strlen(name);
  const char *header_val = ptr;
  while (ptr) {
    ptr = _header_parse_next_parameter2(ptr == header_val, ptr, end, &kv);
    if (ptr && kv.key_len == nlen && strncmp(kv.key, name, nlen) == 0) {
      return kv;
    }
  }
  return (struct iwn_pair) {};
}

struct iwn_pair iwn_wf_header_part_find(struct iwn_wf_req *req, const char *header_name, const char *part_name) {
  struct iwn_val val = iwn_http_request_header_get(req->http, header_name, -1);
  if (!val.len) {
    return (struct iwn_pair) {};
  }
  return iwn_wf_header_val_part_find(val.buf, val.buf + val.len, part_name);
}

IW_INLINE void _request_headers_cookie_parse(struct request *req) {
  struct iwn_pair pair = iwn_wf_header_part_find(&req->base, "cookie", IWN_WF_SESSION_COOKIE_KEY);
  if (pair.val && pair.val_len == IWN_WF_SESSION_ID_LEN) {
    memcpy(req->sid, pair.val, IWN_WF_SESSION_ID_LEN);
  }
}

static iwrc _request_headers_parse(struct request *req) {
  #define _HN_UEC "application/x-www-form-urlencoded"
  #define _HN_MFD "multipart/form-data"

  iwrc rc = 0;
  struct iwn_val val = iwn_http_request_header_get(req->base.http, "content-type", sizeof("content-type") - 1);
  if (val.len > 0) {
    if (val.len >= sizeof(_HN_UEC) - 1 && strncasecmp(val.buf, _HN_UEC, sizeof(_HN_UEC) - 1) == 0) {
      req->base.flags |= IWN_WF_FORM_URL_ENCODED;
    } else if (  val.len > sizeof(_HN_MFD) - 1
              && strncasecmp(val.buf, _HN_MFD, sizeof(_HN_MFD) - 1) == 0) {
      char *ep = val.buf + val.len;
      const char *rp = val.buf += sizeof(_HN_MFD) - 1;
      struct iwn_pair p;
      while ((rp = _header_parse_next_parameter(rp, ep, &p))) {
        if (strncasecmp(p.key, "boundary", sizeof("boundary") - 1) == 0) {
          req->boundary_len = p.val_len;
          req->boundary = iwpool_strndup2(req->pool, p.val, p.val_len);
          break;
        }
      }
      if (!req->boundary) {
        return WF_ERROR_INVALID_FORM_DATA;
      }
      req->base.flags |= IWN_WF_FORM_MULTIPART;
    }
  }

  _request_headers_cookie_parse(req);
  return rc;

  #undef _HN_UEC
  #undef _HN_MFD
}

static bool _route_do_match_next(int pos, struct route_iter *it) {
  struct route *r = it->stack[pos];
  struct request *req = it->req;
  struct iwn_wf_req *wreq = &req->base;
  const char *path_unmatched = wreq->path_unmatched - it->prev_sibling_mlen;
  wreq->path_matched = path_unmatched;

  if (!r) {
    wreq->path_unmatched = path_unmatched;
    it->prev_sibling_mlen = 0;
    return false;
  }

  int mlen = 0;
  size_t unmatched_len = req->path_len - (path_unmatched - req->base.path);

  if (wreq->flags & r->base.flags) { // Request method matched
    if (r->pattern_re) {             // RE
      const char *mpairs[IWRE_MAX_MATCHES];
      pthread_mutex_lock(&r->mtx);
      int mret = iwre_match(r->pattern_re, path_unmatched, mpairs, IWRE_MAX_MATCHES);
      if (mret > 0) {
        int len = (intptr_t) (mpairs[1] - mpairs[0]);
        if ((r->base.flags & IWN_WF_MATCH_PREFIX) || unmatched_len == len) {
          mlen = len;
          for (int i = 2; i < 2 * mret; i += 2) {
            struct iwn_wf_route_submatch *sm = iwpool_alloc(sizeof(*sm), req->pool);
            if (sm) {
              sm->route = &r->base;
              sm->input = path_unmatched;
              sm->sp = mpairs[i];
              sm->ep = mpairs[i + 1];
              if (wreq->last) {
                wreq->last->next = sm;
                wreq->last = sm;
              } else {
                wreq->first = wreq->last = sm;
              }
            }
          }
        }
      }
      pthread_mutex_unlock(&r->mtx);
    } else if (r->pattern) { // Simple path subpart match
      if (  ((r->base.flags & IWN_WF_MATCH_PREFIX) || unmatched_len == r->pattern_len)
         && strncmp(path_unmatched, r->pattern, r->pattern_len) == 0) {
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
      wreq->path_unmatched = path_unmatched;
      it->prev_sibling_mlen = mlen > 0 ? mlen : 0;
    }
  }

  it->mlen[pos] = mlen;
  return mlen != 0;
}

static void _route_iter_init(struct request *req, struct route_iter *it) {
  it->req = req;
  req->base.path_unmatched = req->base.path;
  req->base.path_matched = req->base.path;
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

static iwrc _request_create(struct iwn_http_req *hreq) {
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
  pthread_mutex_init(&req->sess_map_mtx, 0);

  RCC(rc, finish, _request_target_parse(req));
  RCC(rc, finish, _request_method_parse(req));
  RCC(rc, finish, _request_headers_parse(req));

  // Scroll to the first matched route
  _route_iter_init(req, &req->it);
  _route_iter_next(&req->it);

  iwn_http_request_wf_set(hreq, req, _request_on_dispose, _response_headers_write);

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

static const char* _multipart_parse_next(
  IWPOOL           *pool,
  const char       *boundary,
  size_t            boundary_len,
  const char       *rp,
  const char* const ep,
  struct iwn_pairs *parts,
  bool             *eof
  ) {
  #define _HL_CDIS  IW_LLEN("content-disposition")
  #define _HL_CTYPE IW_LLEN("content-type")

  iwrc rc = 0;
  *eof = false;
  if (rp >= ep) {
    *eof = true;
    return 0;
  }

  const char *be = rp + IW_LLEN("--") + boundary_len + IW_LLEN("\r\n" /* or -- */);
  if (be > ep || rp[0] != '-' || rp[1] != '-') {
    return 0;
  }
  rp += IW_LLEN("--");
  if (boundary_len > 0 && strncmp(rp, boundary, boundary_len) != 0) {
    return 0;
  }
  rp += boundary_len;
  if (rp[0] == '-' && rp[1] == '-') {
    *eof = true;
    return 0; // EOF
  }

  struct iwn_pair kv;
  struct iwn_val name = { 0 }, file_name = { 0 },
                 disposition = { 0 }, ctype = { 0 }, data = { 0 };

  while (1) {
    if (ep - rp < 2 || rp[0] != '\r' || rp[1] != '\n') {
      return 0;
    }
    rp += 2;

    const char *hs = rp;
    const char *he = _header_parse_skip_name(hs, ep);
    if (!he) {
      break; // No more headers
    }
    rp = he;
    if (he - hs == _HL_CDIS && strncasecmp(hs, "content-disposition", _HL_CDIS) == 0) {
      int i = 0;
      for (const char *pp = _header_parse_next_parameter(rp, ep, &kv); pp;
           rp = pp,
           pp = _header_parse_next_parameter(pp, ep, &kv),
           ++i) {
        if (i == 0) {
          disposition.len = kv.key_len;
          disposition.buf = (char*) kv.key;
        } else if (kv.val) {
          if (kv.key_len == IW_LLEN("name") && strncasecmp(kv.key, "name", IW_LLEN("name")) == 0) {
            name.len = kv.val_len;
            name.buf = kv.val;
          } else if (kv.key_len == IW_LLEN("filename") && strncasecmp(kv.key, "filename", IW_LLEN("filename")) == 0) {
            file_name.len = kv.val_len;
            file_name.buf = kv.val;
          }
        }
      }
    } else if (he - hs == _HL_CTYPE && strncasecmp(hs, "content-type", _HL_CTYPE) == 0) {
      int i = 0;
      for (const char *pp = _header_parse_next_parameter(rp, ep, &kv); pp;
           rp = pp,
           pp = _header_parse_next_parameter(pp, ep, &kv),
           ++i) {
        if (i == 0) {
          ctype.len = kv.key_len;
          ctype.buf = (char*) kv.key;
        }
      }
      if (i > 0) {
        ctype.len = rp - ctype.buf;
      }
    }
  }

  if (!disposition.len || !name.buf || strncasecmp(disposition.buf, "form-data", disposition.len) != 0) {
    return 0;
  }
  if (ep - rp < 2 || rp[0] != '\r' || rp[1] != '\n') {
    return 0;
  }

  rp += 2;
  be = rp;

  while (ep - rp >= boundary_len + 6) {
    if (  rp[0] == '\r' && rp[1] == '\n'
       && rp[2] == '-' && rp[3] == '-'
       && (boundary_len == 0 || strncmp(rp + 4, boundary, boundary_len) == 0)) {
      rp += boundary_len + 4;

      if ((rp[0] == '\r' && rp[1] == '\n') || (rp[0] == '-' && rp[1] == '-')) {
        data.buf = (char*) be;
        rp -= (boundary_len + 4); // Position at start of \r\n--<boundary>
        data.len = rp - be;
        rp += 2; // Position at start of --<boundary>

        RCC(rc, finish, iwn_pair_add_pool(pool, parts, name.buf, name.len, 0, 0));

        struct iwn_pair *np = parts->last;
        RCA(np->extra = iwpool_calloc(sizeof(*np->extra), pool), finish);
        np->val = data.buf;
        np->val_len = data.len;
        if (file_name.len) {
          RCC(rc, finish,
              iwn_pair_add_pool(pool, np->extra, "filename", IW_LLEN("filename"), file_name.buf, file_name.len));
        }
        if (ctype.len) {
          RCC(rc, finish, iwn_pair_add_pool(pool, np->extra,
                                            "content-type", IW_LLEN("content-type"), ctype.buf, ctype.len));
        }
        return rp;
      }
    }

    ++rp;
  }

finish:
  if (rc) {
    iwlog_ecode_error3(rc);
  }
  return 0;

#undef _HL_CDIS
#undef _HL_CTYPE
}

#ifdef IW_TESTS

const char* dbg_multipart_parse_next(
  IWPOOL           *pool,
  const char       *boundary,
  size_t            boundary_len,
  const char       *rp,
  const char* const ep,
  struct iwn_pairs *parts,
  bool             *eof
  ) {
  return _multipart_parse_next(pool, boundary, boundary_len, rp, ep, parts, eof);
}

#endif

static bool _request_form_multipart_parse(struct request *req) {
  bool eof;
  const char *cp = (char*) req->base.body;
  const char *ep = cp + req->base.body_len;
  while ((cp = _multipart_parse_next(req->pool,
                                     req->boundary, req->boundary_len,
                                     cp, ep, &req->base.form_params, &eof)));
  return eof;
}

IW_INLINE bool _request_form_url_encoded_parse(struct request *req) {
  return 0 == _request_parse_query_inplace(req->pool, &req->base.form_params,
                                           (char*) req->base.body, req->base.body_len);
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
  struct route *pr = 0;

  for (struct route *r = _route_iter_current(&req->it); r; r = _route_iter_next(&req->it)) {
    if (r->base.handler) {
      if (IW_UNLIKELY(pr)) {
        if (r->parent == pr) {
          continue;
        } else {
          pr = 0;
        }
      }
      req->base.route = &r->base;
      rv = r->base.handler(&req->base, r->base.user_data);
      if (rv > 0) {
        if (rv > 1) {
          ok = iwn_http_response_by_code(req->base.http, rv);
        }
        break;
      } else if (rv < 0) {
        if (rv == IWN_WF_RES_SKIP_CHILD_ROUTES) { // Stop further processing of child routes
          pr = r;
          continue;
        } else {
          return false;
        }
      }
    }
  }

  if (ok && rv == 0) { // Delegate all unhandled requests to the root route
    struct ctx *ctx = (void*) req->base.ctx;
    if (ctx->root->base.handler) {
      req->base.route = &ctx->root->base;
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

static bool _request_stream_chunk_process(struct request *req, bool *again) {
  iwrc rc = 0;
  struct iwn_http_req *hreq = req->base.http;
  struct ctx *ctx = (void*) req->base.ctx;
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
    *again = true;
    return true;
  } else {
    if (req->streamed_bytes > 0) {
      int fd = 0;
      if (fwrite(&fd, 1, 1, req->stream_file) != 1) { // Write trailing `\0`
        rc = iwrc_set_errno(IW_ERROR_IO_ERRNO, errno);
        goto finish;
      }
      RCN(finish, fflush(req->stream_file));
      RCN(finish, fd = fileno(req->stream_file));
      void *mm = mmap(0, IW_ROUNDUP(req->streamed_bytes + 1, _aunit), PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
      if (mm == MAP_FAILED) {
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

static bool _request_stream_chunk_next(struct iwn_http_req *hreq, bool *again) {
  struct request *req = iwn_http_request_wf_data(hreq);
  return req && _request_stream_chunk_process(req, again) == true;
}

static bool _request_handler(struct iwn_http_req *hreq) {
  struct ctx *ctx = hreq->server_user_data;
  assert(ctx);
  struct request *req = iwn_http_request_wf_data(hreq);
  if (!req) {
    iwrc rc = _request_create(hreq);
    if (rc) {
      iwlog_ecode_error3(rc);
      return false;
    }
    req = iwn_http_request_wf_data(hreq);
  }
  if (!_route_iter_current(&req->it)) {
    // No routes found.
    // Do not parse request body.
    // Call the root handler or respond 404
    req->base.flags &= ~IWN_WF_FORM_ALL;
    return _request_routes_process(req);
  } else if (iwn_http_request_is_streamed(hreq)) {
    if (ctx->request_file_max_size < 0) {
      iwlog_warn("HTTP large/chunked requests are not allowed by server settings (request_file_max_size)");
      return false;
    }
    iwn_http_request_chunk_next(hreq, _request_stream_chunk_next);
    return true;
  } else {
    return _request_process(req);
  }
}

static iwrc _request_sid_fill(char fout[IWN_WF_SESSION_ID_LEN]) {
  static const char cset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  FILE *f = fopen("/dev/urandom", "r");
  if (!f) {
    return iwrc_set_errno(IW_ERROR_IO_ERRNO, errno);
  }
  if (fread(fout, IWN_WF_SESSION_ID_LEN, 1, f) != 1) {
    fclose(f);
    return iwrc_set_errno(IW_ERROR_IO_ERRNO, errno);
  }
  fclose(f);
  for (int i = 0; i < IWN_WF_SESSION_ID_LEN; ++i) {
    fout[i] = cset[fout[i] % (sizeof(cset) - 1)];
  }
  return 0;
}

IW_INLINE bool _request_sid_exists(struct request *req) {
  return req && req->sid[0] != 0;
}

const char* iwn_wf_session_id(struct iwn_wf_req *req_) {
  struct request *req = (void*) req_;
  if (_request_sid_exists(req)) {
    return req->sid;
  } else {
    return 0;
  }
}

static iwrc _request_sid_ensure(struct request *req) {
  if (_request_sid_exists(req)) {
    return 0;
  }
  char buf[IWN_WF_SESSION_ID_LEN + 1];
  iwrc rc = _request_sid_fill(buf);
  if (!rc) {
    buf[sizeof(buf) - 1] = 0;
    memcpy(req->sid, buf, sizeof(buf));
  } else {
    req->sid[0] = 0;
  }
  return rc;
}

static void _response_headers_write(struct iwn_http_req *hreq) {
  if (iwn_http_connection_is_upgrade(hreq)) {
    // Do not write any extra headers on upgrade
    return;
  }
  struct request *req = iwn_http_request_wf_data(hreq);
  if (_request_sid_exists(req)) {
    iwn_wf_cookie_add(&req->base, IWN_WF_SESSION_COOKIE_KEY, req->sid, (struct iwn_wf_cookie_opts) {
      .path = "/",
      .httponly = true,
      .max_age_sec = hreq->session_cookie_max_age_sec,
      .extra = hreq->session_cookie_params ? hreq->session_cookie_params : "; samesite=lax"
    });
  }
}

iwrc iwn_wf_route(const struct iwn_wf_route *spec, struct iwn_wf_route **out_route) {
  if (!spec) {
    return IW_ERROR_INVALID_ARGS;
  }
  struct route *route;
  if (out_route) {
    *out_route = 0;
  }
  struct ctx *ctx = (void*) spec->ctx;
  if (spec->parent) {
    ((struct iwn_wf_route*) spec->parent)->flags |= IWN_WF_MATCH_PREFIX;
    for (const struct iwn_wf_route *p = spec->parent; !ctx && p; p = p->parent) {
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
  RCR(_init());
  if (!out_ctx) {
    return IW_ERROR_INVALID_ARGS;
  }
  struct iwn_wf_route default_root_route = {
    .tag = "root"
  };
  *out_ctx = 0;
  if (!root_route_spec) {
    root_route_spec = &default_root_route;
  }
  IWPOOL *pool = iwpool_create_empty();
  if (!pool) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }

  iwrc rc = 0;
  struct ctx *ctx = 0;
  RCA(ctx = iwpool_calloc(sizeof(*ctx), pool), finish);
  ctx->pool = pool;
  ctx->server_fd = -1;
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

int iwn_wf_server_fd_get(struct iwn_wf_ctx *ctx) {
  return ((struct ctx*) ctx)->server_fd;
}

iwrc iwn_wf_session_id_set(struct iwn_wf_req *req_, const char *sid) {
  if (!sid || strlen(sid) != IWN_WF_SESSION_ID_LEN) {
    return IW_ERROR_INVALID_ARGS;
  }
  struct request *req = (void*) req_;
  pthread_mutex_lock(&req->sess_map_mtx);
  memcpy(req->sid, sid, IWN_WF_SESSION_ID_LEN + 1);
  if (req->sess_map) {
    iwhmap_clear(req->sess_map);
  }
  pthread_mutex_unlock(&req->sess_map_mtx);
  return 0;
}

const char* iwn_wf_session_get(struct iwn_wf_req *req_, const char *key) {
  struct request *req = (void*) req_;
  struct ctx *ctx = (void*) req->base.ctx;
  if (_request_sid_exists(req)) {
    pthread_mutex_lock(&req->sess_map_mtx);
    char *val = req->sess_map ? iwhmap_get(req->sess_map, key) : 0;
    if (!val) {
      val = ctx->sst.get(&ctx->sst, req->sid, key);
      if (val) {
        if (!req->sess_map) {
          req->sess_map = iwhmap_create_str(iwhmap_kv_free);
          if (!req->sess_map) {
            pthread_mutex_unlock(&req->sess_map_mtx);
            return 0;
          }
        }
        char *k = strdup(key);
        if (k) {
          if (iwhmap_put(req->sess_map, k, val)) {
            free(val);
            free(k);
            val = 0;
          }
        } else {
          free(val);
          val = 0;
        }
      }
    }
    pthread_mutex_unlock(&req->sess_map_mtx);
    return val;
  } else {
    return 0;
  }
}

iwrc iwn_wf_session_put(struct iwn_wf_req *req_, const char *key, const char *data) {
  if (data == 0) {
    iwn_wf_session_del(req_, key);
    return 0;
  }
  struct request *req = (void*) req_;
  struct ctx *ctx = (void*) req->base.ctx;
  pthread_mutex_lock(&req->sess_map_mtx);
  RCR(_request_sid_ensure(req));
  if (req->sess_map) {
    iwhmap_remove(req->sess_map, key);
  }
  iwrc rc = ctx->sst.put(&ctx->sst, req->sid, key, data);
  pthread_mutex_unlock(&req->sess_map_mtx);
  return rc;
}

iwrc iwn_wf_session_printf_va(struct iwn_wf_req *req, const char *key, const char *fmt, va_list va) {
  iwrc rc = 0;
  char buf[1024];
  char *wp = buf;

  va_list cva;
  va_copy(cva, va);

  int size = vsnprintf(wp, sizeof(buf), fmt, va);
  if (size < 0) {
    return IW_ERROR_FAIL;
  }
  if (size >= sizeof(buf)) {
    RCA(wp = malloc(size + 1), finish);
    size = vsnprintf(wp, size + 1, fmt, cva);
    if (size < 0) {
      rc = IW_ERROR_FAIL;
      goto finish;
    }
  }

  rc = iwn_wf_session_put(req, key, wp);

finish:
  va_end(cva);
  if (wp != buf) {
    free(wp);
  }
  return rc;
}

iwrc iwn_wf_session_printf(struct iwn_wf_req *req, const char *key, const char *fmt, ...) {
  va_list va;
  va_start(va, fmt);
  iwrc rc = iwn_wf_session_printf_va(req, key, fmt, va);
  va_end(va);
  return rc;
}

void iwn_wf_session_del(struct iwn_wf_req *req_, const char *key) {
  struct request *req = (void*) req_;
  struct ctx *ctx = (void*) req->base.ctx;
  if (_request_sid_exists(req)) {
    pthread_mutex_lock(&req->sess_map_mtx);
    if (req->sess_map) {
      iwhmap_remove(req->sess_map, key);
    }
    ctx->sst.del(&ctx->sst, req->sid, key);
    pthread_mutex_unlock(&req->sess_map_mtx);
  }
}

void iwn_wf_session_clear(struct iwn_wf_req *req_) {
  struct request *req = (void*) req_;
  struct ctx *ctx = (void*) req->base.ctx;
  if (_request_sid_exists(req)) {
    ctx->sst.clear(&ctx->sst, req->sid);
    pthread_mutex_lock(&req->sess_map_mtx);
    req->sid[0] = 0;
    iwhmap_clear(req->sess_map);
    pthread_mutex_unlock(&req->sess_map_mtx);
  }
}

iwrc iwn_wf_cookie_add(
  struct iwn_wf_req              *req,
  const char                     *name,
  const char                     *value,
  const struct iwn_wf_cookie_opts opts
  ) {
  iwrc rc = 0;
  IWXSTR *xstr;

  RCA(xstr = iwxstr_new(), finish);
  RCC(rc, finish, iwxstr_printf(xstr, "%s=\"%s\"", name, value));
  if (opts.max_age_sec < 0) {
    RCC(rc, finish, iwxstr_cat(xstr, "; Max-Age=0", IW_LLEN("; Max-Age=0")));
  } else if (opts.max_age_sec > 0) {
    RCC(rc, finish, iwxstr_printf(xstr, "; Max-Age=%d", opts.max_age_sec));
  }
  if (opts.path) {
    RCC(rc, finish, iwxstr_printf(xstr, "; Path=%s", opts.path));
  }
  if (opts.domain) {
    RCC(rc, finish, iwxstr_printf(xstr, "; Domain=%s", opts.domain));
  }
  if (opts.httponly) {
    RCC(rc, finish, iwxstr_cat(xstr, "; Httponly", IW_LLEN("; Httponly")));
  }
  if (opts.secure || iwn_http_request_is_secure(req->http)) {
    RCC(rc, finish, iwxstr_cat(xstr, "; Secure", IW_LLEN("; Secure")));
  }
  if (opts.extra) {
    RCC(rc, finish, iwxstr_cat2(xstr, opts.extra));
  }

  rc = iwn_http_response_header_add(req->http, "Set-Cookie", iwxstr_ptr(xstr), iwxstr_size(xstr));

finish:
  iwxstr_destroy(xstr);
  return rc;
}

struct iwn_wf_route_submatch* iwn_wf_request_submatch_first(const struct iwn_wf_req *req) {
  struct iwn_wf_route *r = req->route;
  for (struct iwn_wf_route_submatch *s = req->first; s; s = s->next) {
    if (s->route == r) {
      return s;
    }
  }
  return 0;
}

struct iwn_wf_route_submatch* iwn_wf_request_submatch_last(const struct iwn_wf_req *req) {
  struct iwn_wf_route *r = req->route;
  if (req->last->route == r) {
    return req->last;
  }
  struct iwn_wf_route_submatch *ss = 0;
  for (struct iwn_wf_route_submatch *s = req->first; s; s = s->next) {
    if (s->route == r) {
      ss = s;
    }
  }
  return ss;
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
  http.on_server_dispose = _server_on_dispose;
  http.request_handler = _request_handler;

  http.user_data = ctx;
  http.poller = spec.poller;
  http.listen = spec.listen;
  http.port = spec.port;

  memcpy(&http.ssl, &spec.ssl, sizeof(http.ssl));

  http.socket_queue_size = spec.socket_queue_size;
  http.request_buf_max_size = spec.request_buf_max_size;
  http.request_buf_size = spec.request_buf_size;
  http.request_timeout_keepalive_sec = spec.request_timeout_keepalive_sec;
  http.request_timeout_sec = spec.request_timeout_sec;
  http.request_token_max_len = spec.request_token_max_len;
  http.request_max_headers_count = spec.request_max_headers_count;

  struct iwn_wf_session_store *sst = &spec.session_store;
  if (memcmp(sst, &(struct iwn_wf_session_store) {}, sizeof(*sst)) == 0) {
    sst_inmem_create(sst);
  }
  if (  !sst->clear
     || !sst->del
     || !sst->get
     || !sst->put
     || !sst->dispose) {
    iwlog_ecode_error2(IW_ERROR_INVALID_ARGS, "(struct iwn_wf_server_spec).session_store is not initialized");
    return IW_ERROR_INVALID_ARGS;
  }
  ctx->sst = *sst;

  return iwn_http_server_create(&http, &ctx->server_fd);
}

void iwn_wf_destroy(struct iwn_wf_ctx *ctx_) {
  struct ctx *ctx = (void*) ctx_;
  if (ctx) {
    if (ctx->poller && ctx->server_fd > -1) {
      iwn_poller_remove(ctx->poller, ctx->server_fd);
    } else {
      _ctx_destroy(ctx);
    }
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
    case WF_ERROR_UNSUPPORTED_HTTP_METHOD:
      return "Unsupported HTTP method (WF_ERROR_UNSUPPORTED_HTTP_METHOD)";
    case WF_ERROR_MAX_NESTED_ROUTES:
      return "Reached the maximum number of nested routes: 127 (WF_ERROR_MAX_NESTED_ROUTES)";
    case WF_ERROR_CURL_API:
      return "CUrl API call error (WF_ERROR_CURL_API)";
  }
  return 0;
}

struct _pctx {
  int   indent;
  int  *num;
  FILE *out;
};

static void _route_print_flags(IWXSTR *xstr, uint32_t f) {
  int c = 0;
  if ((f & IWN_WF_METHODS_ALL) == IWN_WF_METHODS_ALL) {
    iwxstr_cat2(xstr, "ALL");
    return;
  }
  if (f & IWN_WF_GET) {
    if (c++) {
      iwxstr_cat2(xstr, ",");
    }
    iwxstr_cat2(xstr, "GET");
  }
  if (f & IWN_WF_POST) {
    if (c++) {
      iwxstr_cat2(xstr, ",");
    }
    iwxstr_cat2(xstr, "POST");
  }
  if (f & IWN_WF_PUT) {
    if (c++) {
      iwxstr_cat2(xstr, ",");
    }
    iwxstr_cat2(xstr, "PUT");
  }
  if (f & IWN_WF_DELETE) {
    if (c++) {
      iwxstr_cat2(xstr, ",");
    }
    iwxstr_cat2(xstr, "DELETE");
  }
  if (f & IWN_WF_PATCH) {
    if (c++) {
      iwxstr_cat2(xstr, ",");
    }
    iwxstr_cat2(xstr, "PATCH");
  }
  if (f & IWN_WF_HEAD) {
    if (c++) {
      iwxstr_cat2(xstr, ",");
    }
    iwxstr_cat2(xstr, "HEAD");
  }
  if (f & IWN_WF_OPTIONS) {
    if (c++) {
      iwxstr_cat2(xstr, ",");
    }
    iwxstr_cat2(xstr, "OPTIONS");
  }
}

static void _route_print(struct _pctx ctx, struct route *r) {
  *ctx.num += 1;
  fprintf(ctx.out, "%04d ", *ctx.num);
  for (int i = 0; i < ctx.indent; ++i) {
    fprintf(ctx.out, "  ");
  }
  IWXSTR *xstr = iwxstr_new();
  if (!xstr) {
    return;
  }
  iwxstr_cat2(xstr, r->pattern_re ? "{" : "[");
  if (r->base.tag) {
    iwxstr_cat2(xstr, r->base.tag);
    iwxstr_cat2(xstr, ":");
  }
  if (r->pattern) {
    iwxstr_cat2(xstr, r->pattern);
  } else {
    iwxstr_cat2(xstr, "*");
  }
  iwxstr_cat2(xstr, (r->base.flags & IWN_WF_MATCH_PREFIX) ? "> " : "] ");
  if (r->parent != 0) {
    _route_print_flags(xstr, r->base.flags);
  }
  fprintf(ctx.out, "%s\n", iwxstr_ptr(xstr));
  iwxstr_destroy(xstr);
  for (struct route *n = r->child; n; n = n->next) {
    _route_print((struct _pctx) {
      .out = ctx.out,
      .indent = ctx.indent + 1,
      .num = ctx.num
    }, n);
  }
}

void iwn_wf_route_print(const struct iwn_wf_route *route, FILE *out) {
  int num = 0;
  struct route *r = (void*) route;
  if (r) {
    _route_print((struct _pctx) {
      .out = out,
      .num = &num,
    }, r);
  }
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

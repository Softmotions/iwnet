/*
 * Tests of the iwn_wf web framework.
 *
 * The framework internals are exercised in-process:
 *
 *  - Route tree construction: simple and regexp patterns, nested routes, method
 *    matching, prefix matching and route registration error paths.
 *  - Route matching against a request: the request path/query/method/headers are
 *    parsed with the same code used by the live server (`dbg_request_parse()`
 *    drives `_request_target_parse()`, `_request_method_parse()` and
 *    `_request_headers_parse()` over a stub `iwn_http_req`), then the route
 *    iterator is run over the parsed request.
 *  - Pure helpers: query string parsing, `Cookie`/`Content-Type` style header
 *    parameter parsing, multipart form-data parsing.
 *  - Session storage: the in-memory session store (`iwn_wf_sst_inmem.c`) and the
 *    `iwn_wf_session_*` request API on top of it.
 *
 * No network IO is involved: a fake `struct iwn_http_req` with an operations
 * table returning canned request data stands in for a real connection.
 *
 * HTTP level tests of the framework (routing, forms, file serving, sessions over
 * a real socket) live in `server2.c`/`server2-tests-run.sh`.
 */

#include "iwtests.h"
#include "iwn_wf_internal.h"
#include "iwn_wf_sst_inmem.h"
#include "iwn_codec.h"

#include <iowow/iwlog.h>

#include <stdio.h>
#include <string.h>
#include <strings.h>

static struct iwn_wf_ctx *ctx;

static int _root_handler(struct iwn_wf_req *req, void *user_data) {
  return 0;
}

static int _route_handler(struct iwn_wf_req *req, void *user_data) {
  return 0;
}

///////////////////////////////////////////////////////////////////////////
//                        Fake http request                               //
///////////////////////////////////////////////////////////////////////////

static struct iwn_val _fake_target;
static struct iwn_val _fake_method;
static struct iwn_pairs _fake_headers;

static struct iwn_val _fake_request_target(struct iwn_http_req *req) {
  return _fake_target;
}

static struct iwn_val _fake_request_method(struct iwn_http_req *req) {
  return _fake_method;
}

static struct iwn_val _fake_request_header_get(struct iwn_http_req *req, const char *name, ssize_t name_len) {
  if (name_len < 0) {
    name_len = strlen(name);
  }
  for (struct iwn_pair *p = _fake_headers.first; p; p = p->next) {
    if (p->key_len == (size_t) name_len && strncasecmp(p->key, name, name_len) == 0) {
      return (struct iwn_val) {
               .buf = p->val,
               .len = p->val_len
      };
    }
  }
  return (struct iwn_val) {};
}

static const struct iwn_http_req_ops _fake_http_ops = {
  .request_target = _fake_request_target,
  .request_method = _fake_request_method,
  .request_header_get = _fake_request_header_get,
};

static struct iwn_http_req _fake_http = {
  .impl = &_fake_http_ops,
};

static struct request* _request_alloc(struct iwpool *pool) {
  struct request *req = iwpool_calloc(sizeof(*req), pool);
  IW_TEST_ASSERT_FATAL(req);
  pthread_mutex_init(&req->sess_map_mtx, 0);
  req->pool = pool;
  req->base.ctx = ctx;
  return req;
}

static struct request* _request_create(const char *path, int method, struct iwpool *pool) {
  struct request *req = _request_alloc(pool);
  req->base.path = path;
  req->path_len = strlen(path);
  req->base.path_unmatched = path;
  req->base.flags = method;
  return req;
}

/// Creates a request whose target/method/headers are supplied by the fake http request.
/// The request owns its memory pool, dispose it with `dbg_request_destroy()`.
static struct request* _fake_request(struct iwpool **out_pool, const char *target, const char *method) {
  memset(&_fake_headers, 0, sizeof(_fake_headers));
  _fake_target = (struct iwn_val) {
    .buf = (char*) target,
    .len = strlen(target)
  };
  _fake_method = (struct iwn_val) {
    .buf = (char*) method,
    .len = strlen(method)
  };
  struct iwpool *pool = iwpool_create_empty();
  IW_TEST_ASSERT_FATAL(pool);
  if (out_pool) {
    *out_pool = pool;
  }
  struct request *req = _request_alloc(pool);
  req->base.http = &_fake_http;
  return req;
}

static void _fake_header_add(struct iwpool *pool, const char *name, const char *val) {
  iwrc rc = iwn_pair_add_pool_all(pool, &_fake_headers, name, -1, val, -1);
  IW_TEST_ASSERT_FATAL(rc == 0);
}

static struct route* _request_first_matched(const char *path, int methods, struct route_iter *oit) {
  struct iwpool *pool = iwpool_create_empty();
  IW_TEST_ASSERT_FATAL(pool);
  struct request *req = _request_create(path, methods, pool);
  struct route_iter it = { 0 };
  dbg_route_iter_init(req, &it);
  struct route *route = dbg_route_iter_next(&it);
  if (oit) {
    memcpy(oit, &it, sizeof(*oit));
  } else {
    dbg_request_destroy(req);
  }
  return route;
}

static int _pairs_count(const struct iwn_pairs *pairs) {
  int n = 0;
  for (struct iwn_pair *p = pairs->first; p; p = p->next) {
    ++n;
  }
  return n;
}

///////////////////////////////////////////////////////////////////////////
//                            Route matching                              //
///////////////////////////////////////////////////////////////////////////

static void test_regexp_matching(void) {
  iwrc rc = 0;
  struct route_iter it = { 0 };
  struct route *r;
  struct iwn_wf_route *p;

  RCC(rc, finish, iwn_wf_create(&(struct iwn_wf_route) {
    .handler = _root_handler,
    .tag = "root"
  }, &ctx));

  RCC(rc, finish, iwn_wf_route(&(struct iwn_wf_route) {
    .ctx = ctx,
    .pattern = "^/fo([^/]+)",
    .handler = _route_handler,
  }, &p));

  RCC(rc, finish, iwn_wf_route(&(struct iwn_wf_route) {
    .ctx = ctx,
    .pattern = "^/b(a)(rr?)",
    .handler = _route_handler,
    .tag = "bar0",
  }, 0));

  r = _request_first_matched("/foo", IWN_WF_GET, &it);
  IW_TEST_ASSERT(r);
  dbg_request_destroy(it.req);

finish:
  iwn_wf_destroy(ctx);
  ctx = 0;
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
}

static void test_simple_matching(void) {
  iwrc rc = 0;
  struct route_iter it = { 0 };
  struct route *r, *r2;
  struct iwn_wf_route *p, *p2;

  RCC(rc, finish, iwn_wf_create(&(struct iwn_wf_route) {
    .handler = _root_handler,
    .tag = "root"
  }, &ctx));

  RCC(rc, finish, iwn_wf_route(&(struct iwn_wf_route) {
    .ctx = ctx,
    .pattern = "/foo",
    .handler = _route_handler,
  }, &p));

  RCC(rc, finish, iwn_wf_route(&(struct iwn_wf_route) {
    .ctx = ctx,
    .pattern = "/bar",
    .flags = IWN_WF_GET | IWN_WF_PUT,
    .handler = _route_handler,
    .tag = "bar0",
  }, 0));

  RCC(rc, finish, iwn_wf_route(&(struct iwn_wf_route) {
    .parent = p,
    .pattern = "/zaz",
    .handler = _route_handler,
  }, 0));

  RCC(rc, finish, iwn_wf_route(&(struct iwn_wf_route) {
    .parent = p,
    .pattern = "/bar",
    .handler = _route_handler,
    .tag = "bar2"
  }, &p2));

  RCC(rc, finish, iwn_wf_route(&(struct iwn_wf_route) {
    .parent = p2,
    .handler = _route_handler,
    .tag = "bar2_nested"
  }, 0));

  r = _request_first_matched("/bar", IWN_WF_PUT, &it);
  IW_TEST_ASSERT(r);
  if (r) {
    IW_TEST_ASSERT(strcmp(r->pattern, "/bar") == 0);
  }
  dbg_request_destroy(it.req);

  r = _request_first_matched("/bar", IWN_WF_POST, &it);
  IW_TEST_ASSERT(!rc);
  dbg_request_destroy(it.req);

  r = _request_first_matched("/foo", IWN_WF_GET, &it);
  IW_TEST_ASSERT(r);
  if (r) {
    IW_TEST_ASSERT(strcmp(r->pattern, "/foo") == 0);
  }
  r = dbg_route_iter_next(&it);
  IW_TEST_ASSERT(!r);
  dbg_request_destroy(it.req);

  r = _request_first_matched("/foo/bar", IWN_WF_GET, &it);
  IW_TEST_ASSERT_FATAL(r);
  IW_TEST_ASSERT_FATAL(strcmp(r->pattern, "/foo") == 0);

  r2 = dbg_route_iter_next(&it);
  IW_TEST_ASSERT_FATAL(r2);
  IW_TEST_ASSERT(r2->parent == r);
  IW_TEST_ASSERT_FATAL(strcmp(r2->pattern, "/bar") == 0);

  r = dbg_route_iter_next(&it);
  IW_TEST_ASSERT_FATAL(r);
  IW_TEST_ASSERT(r->parent == r2);
  IW_TEST_ASSERT(strcmp(r->base.tag, "bar2_nested") == 0);
  dbg_request_destroy(it.req);

finish:
  iwn_wf_destroy(ctx);
  ctx = 0;
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
}

/// A parent route matches only a prefix of the request path when it has child routes,
/// while a route without children requires the exact path match.
static void test_prefix_matching(void) {
  iwrc rc = 0;
  struct iwn_wf_route *parent = 0;

  RCC(rc, finish, iwn_wf_create(&(struct iwn_wf_route) {
    .handler = _root_handler,
    .tag = "root"
  }, &ctx));

  RCC(rc, finish, iwn_wf_route(&(struct iwn_wf_route) {
    .ctx = ctx,
    .pattern = "/api",
    .handler = _route_handler,
    .tag = "api",
  }, &parent));

  IW_TEST_ASSERT_FATAL((parent->flags & IWN_WF_MATCH_PREFIX) == 0);

  RCC(rc, finish, iwn_wf_route(&(struct iwn_wf_route) {
    .parent = parent,
    .pattern = "/v1",
    .handler = _route_handler,
    .tag = "v1",
  }, 0));

  IW_TEST_ASSERT(parent->flags & IWN_WF_MATCH_PREFIX);

  struct route_iter it = { 0 };
  struct route *r = _request_first_matched("/api/v1", IWN_WF_GET, &it);
  IW_TEST_ASSERT_FATAL(r);
  IW_TEST_ASSERT(strcmp(r->base.tag, "api") == 0);
  r = dbg_route_iter_next(&it);
  IW_TEST_ASSERT_FATAL(r);
  IW_TEST_ASSERT(strcmp(r->base.tag, "v1") == 0);
  IW_TEST_ASSERT(!dbg_route_iter_next(&it));
  dbg_request_destroy(it.req);

  // Exact match of a route without children is required
  RCC(rc, finish, iwn_wf_route(&(struct iwn_wf_route) {
    .ctx = ctx,
    .pattern = "/exact",
    .handler = _route_handler,
    .tag = "exact",
  }, 0));
  r = _request_first_matched("/exactly", IWN_WF_GET, &it);
  IW_TEST_ASSERT(!r);
  dbg_request_destroy(it.req);

finish:
  iwn_wf_destroy(ctx);
  ctx = 0;
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
}

/// Route registration error paths.
static void test_route_errors(void) {
  iwrc rc = 0;
  struct iwn_wf_ctx *ctx2 = 0;
  struct iwn_wf_route *foreign_route = 0;

  IW_TEST_ASSERT_EQUAL_FATAL(iwn_wf_route(0, 0), IW_ERROR_INVALID_ARGS);
  IW_TEST_ASSERT_EQUAL_FATAL(iwn_wf_create(0, 0), IW_ERROR_INVALID_ARGS);

  // No web-framework context
  IW_TEST_ASSERT_EQUAL_FATAL(iwn_wf_route(&(struct iwn_wf_route) {
    .pattern = "/noctx",
    .handler = _route_handler,
  }, 0), IW_ERROR_INVALID_ARGS);

  RCC(rc, finish, iwn_wf_create(&(struct iwn_wf_route) {
    .handler = _root_handler,
    .tag = "root"
  }, &ctx));

  // Invalid regular expression
  IW_TEST_ASSERT_EQUAL_FATAL(iwn_wf_route(&(struct iwn_wf_route) {
    .ctx = ctx,
    .pattern = "^/fo([",
    .handler = _route_handler,
  }, 0), WF_ERROR_REGEXP_INVALID);

  // Parent route from a different context
  RCC(rc, finish, iwn_wf_create(&(struct iwn_wf_route) {
    .handler = _root_handler,
    .tag = "root2"
  }, &ctx2));
  RCC(rc, finish, iwn_wf_route(&(struct iwn_wf_route) {
    .ctx = ctx2,
    .pattern = "/foreign",
    .handler = _route_handler,
  }, &foreign_route));
  IW_TEST_ASSERT_EQUAL_FATAL(iwn_wf_route(&(struct iwn_wf_route) {
    .ctx = ctx,
    .parent = foreign_route,
    .pattern = "/nested",
    .handler = _route_handler,
  }, 0), WF_ERROR_PARENT_ROUTE_FROM_DIFFERENT_CONTEXT);

  // Max nested routes
  {
    struct iwn_wf_route *prev = 0;
    int created = 0;
    bool limit_hit = false;
    for (int i = 0; i < ROUTE_MATCHING_STACK_SIZE + 8; ++i) {
      struct iwn_wf_route *r = 0;
      struct iwn_wf_route spec = {
        .parent = prev,
        .pattern = "/n",
        .handler = _route_handler,
      };
      if (!prev) {
        spec.ctx = ctx;
      }
      iwrc rci = iwn_wf_route(&spec, &r);
      if (rci) {
        IW_TEST_ASSERT_EQUAL_FATAL(rci, WF_ERROR_MAX_NESTED_ROUTES);
        limit_hit = true;
        break;
      }
      prev = r;
      ++created;
    }
    IW_TEST_ASSERT(limit_hit);
    IW_TEST_ASSERT(created > 0);
    IW_TEST_ASSERT(created < ROUTE_MATCHING_STACK_SIZE);
  }

finish:
  iwn_wf_destroy(ctx);
  ctx = 0;
  iwn_wf_destroy(ctx2);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
}

/// Route tree printing (`iwn_wf_route_print()`).
static void test_route_print(void) {
  iwrc rc = 0;
  struct iwn_wf_route *foo = 0;
  FILE *f = 0;
  char buf[2048];

  RCC(rc, finish, iwn_wf_create(&(struct iwn_wf_route) {
    .handler = _root_handler,
    .tag = "root"
  }, &ctx));

  RCC(rc, finish, iwn_wf_route(&(struct iwn_wf_route) {
    .ctx = ctx,
    .pattern = "/foo",
    .handler = _route_handler,
    .tag = "foo",
  }, &foo));

  RCC(rc, finish, iwn_wf_route(&(struct iwn_wf_route) {
    .parent = foo,
    .pattern = "/bar",
    .handler = _route_handler,
    .tag = "bar",
    .flags = IWN_WF_POST,
  }, 0));

  f = tmpfile();
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(f);
  iwn_wf_route_print(ctx->root, f);
  long len = ftell(f);
  IW_TEST_ASSERT_FATAL(len > 0 && len < (long) sizeof(buf));
  rewind(f);
  IW_TEST_ASSERT_EQUAL_FATAL(fread(buf, 1, (size_t) len, f), (size_t) len);
  buf[len] = '\0';

  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(strstr(buf, "[root:*] "));
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(strstr(buf, "[foo:/foo> GET"));
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(strstr(buf, "[bar:/bar] POST"));

  int lines = 0;
  for (const char *p = buf; *p; ++p) {
    if (*p == '\n') {
      ++lines;
    }
  }
  IW_TEST_ASSERT_EQUAL_FATAL(lines, 3);

finish:
  if (f) {
    fclose(f);
  }
  iwn_wf_destroy(ctx);
  ctx = 0;
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
}

/// Regexp route submatches accessors.
static void test_regexp_submatches(void) {
  iwrc rc = 0;
  struct iwn_wf_route *p = 0;

  RCC(rc, finish, iwn_wf_create(&(struct iwn_wf_route) {
    .handler = _root_handler,
    .tag = "root"
  }, &ctx));

  RCC(rc, finish, iwn_wf_route(&(struct iwn_wf_route) {
    .ctx = ctx,
    .pattern = "^/sub/([a-z]+)/([0-9]+)",
    .handler = _route_handler,
    .tag = "sub",
  }, &p));

  struct route_iter it = { 0 };
  struct route *r = _request_first_matched("/sub/abc/42", IWN_WF_GET, &it);
  IW_TEST_ASSERT_FATAL(r);
  IW_TEST_ASSERT(strcmp(r->base.tag, "sub") == 0);
  it.req->base.route = &r->base;

  struct iwn_wf_route_submatch *sm = iwn_wf_request_submatch_first(&it.req->base);
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(sm);
  IW_TEST_ASSERT_NSTR_EQUAL(sm->sp, "abc", 3);
  IW_TEST_ASSERT_EQUAL_FATAL(sm->ep - sm->sp, 3);

  sm = iwn_wf_request_submatch_nth(&it.req->base, 2);
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(sm);
  IW_TEST_ASSERT_NSTR_EQUAL(sm->sp, "42", 2);
  IW_TEST_ASSERT_PTR_NULL_FATAL(iwn_wf_request_submatch_nth(&it.req->base, 3));

  sm = iwn_wf_request_submatch_last(&it.req->base);
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(sm);
  IW_TEST_ASSERT_NSTR_EQUAL(sm->sp, "42", 2);
  dbg_request_destroy(it.req);

  // A route without regexp submatches must not crash submatch accessors
  struct iwn_wf_route *exact = 0;
  RCC(rc, finish, iwn_wf_route(&(struct iwn_wf_route) {
    .ctx = ctx,
    .pattern = "/exact",
    .handler = _route_handler,
    .tag = "exact",
  }, &exact));
  r = _request_first_matched("/exact", IWN_WF_GET, &it);
  IW_TEST_ASSERT_FATAL(r);
  IW_TEST_ASSERT_PTR_NULL_FATAL(it.req->base.first);
  it.req->base.route = &r->base;
  IW_TEST_ASSERT_PTR_NULL_FATAL(iwn_wf_request_submatch_first(&it.req->base));
  IW_TEST_ASSERT_PTR_NULL_FATAL(iwn_wf_request_submatch_last(&it.req->base));
  IW_TEST_ASSERT_PTR_NULL_FATAL(iwn_wf_request_submatch_nth(&it.req->base, 1));
  dbg_request_destroy(it.req);

finish:
  iwn_wf_destroy(ctx);
  ctx = 0;
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
}

///////////////////////////////////////////////////////////////////////////
//                          Request parsing                               //
///////////////////////////////////////////////////////////////////////////

static void test_query_parsing(void) {
  struct iwpool *pool = iwpool_create_empty();
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(pool);

  struct iwn_pairs pairs = { 0 };
  char q[] = "foo=bar&baz=a%40z&a&b=&c=1+2&d=%4&e=%zz&f=%41%42";
  IW_TEST_ASSERT_EQUAL_FATAL(iwn_wf_parse_query_inplace(pool, &pairs, q, strlen(q)), 0);
  IW_TEST_ASSERT_EQUAL_FATAL(_pairs_count(&pairs), 8);

  struct iwn_pair *p = iwn_pair_find(&pairs, "foo", -1);
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(p);
  IW_TEST_ASSERT_NSTR_EQUAL(p->val, "bar", 3);

  p = iwn_pair_find(&pairs, "baz", -1);
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(p);
  IW_TEST_ASSERT_NSTR_EQUAL(p->val, "a@z", 3);

  // Key without a value
  p = iwn_pair_find(&pairs, "a", -1);
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(p);
  IW_TEST_ASSERT_EQUAL_FATAL(p->val_len, 0);

  // Empty value
  p = iwn_pair_find(&pairs, "b", -1);
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(p);
  IW_TEST_ASSERT_EQUAL_FATAL(p->val_len, 0);

  // `+` is a space in a query string
  p = iwn_pair_find(&pairs, "c", -1);
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(p);
  IW_TEST_ASSERT_NSTR_EQUAL(p->val, "1 2", 3);

  // Malformed escape sequences are preserved as is
  p = iwn_pair_find(&pairs, "d", -1);
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(p);
  IW_TEST_ASSERT_NSTR_EQUAL(p->val, "%4", 2);

  p = iwn_pair_find(&pairs, "e", -1);
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(p);
  IW_TEST_ASSERT_NSTR_EQUAL(p->val, "%zz", 3);

  p = iwn_pair_find(&pairs, "f", -1);
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(p);
  IW_TEST_ASSERT_NSTR_EQUAL(p->val, "AB", 2);

  // Duplicated keys are preserved
  struct iwn_pairs dup = { 0 };
  char q2[] = "a=1&a=2";
  IW_TEST_ASSERT_EQUAL_FATAL(iwn_wf_parse_query_inplace(pool, &dup, q2, strlen(q2)), 0);
  IW_TEST_ASSERT_EQUAL_FATAL(_pairs_count(&dup), 2);

  // Empty keys are skipped
  struct iwn_pairs empty = { 0 };
  char q3[] = "a=1&&=2&b=3";
  IW_TEST_ASSERT_EQUAL_FATAL(iwn_wf_parse_query_inplace(pool, &empty, q3, strlen(q3)), 0);
  IW_TEST_ASSERT_EQUAL_FATAL(_pairs_count(&empty), 2);
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(iwn_pair_find(&empty, "a", -1));
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(iwn_pair_find(&empty, "b", -1));

  // Empty query
  IW_TEST_ASSERT_EQUAL_FATAL(iwn_wf_parse_query_inplace(pool, &empty, 0, 0), 0);
  IW_TEST_ASSERT_EQUAL_FATAL(iwn_wf_parse_query_inplace(pool, &empty, q3, 0), 0);

  iwpool_destroy(pool);
}

static void test_header_parsing(void) {
  // Header values are parsed in place (quoted values are unescaped), so they must be writable
  char cookie[] = "_ga=GA1.2.258852180.1582174090; sessionid=AJyF7R984Ezziz7nYgmezxtxmMbT1Cyr";
  struct iwn_pair pv = iwn_wf_header_val_part_find(cookie, cookie + strlen(cookie), "sessionid");
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(pv.key);
  IW_TEST_ASSERT_EQUAL_FATAL(pv.val_len, IWN_WF_SESSION_ID_LEN);
  IW_TEST_ASSERT_NSTR_EQUAL(pv.val, "AJyF7R984Ezziz7nYgmezxtxmMbT1Cyr", IWN_WF_SESSION_ID_LEN);

  pv = iwn_wf_header_val_part_find(cookie, cookie + strlen(cookie), "_ga");
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(pv.key);
  IW_TEST_ASSERT_NSTR_EQUAL(pv.val, "GA1.2.258852180.1582174090", IW_LLEN("GA1.2.258852180.1582174090"));

  pv = iwn_wf_header_val_part_find(cookie, cookie + strlen(cookie), "absent");
  IW_TEST_ASSERT_PTR_NULL_FATAL(pv.key);

  // Quoted and escaped parameter values
  char ctype[] = "text/plain; charset=\"utf-8 x\"; name=\"f\\oo.html\"; boundary=zzz";
  const char *ep = ctype + strlen(ctype);
  pv = iwn_wf_header_val_part_find(ctype, ep, "charset");
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(pv.key);
  IW_TEST_ASSERT_NSTR_EQUAL(pv.val, "utf-8 x", 7);

  pv = iwn_wf_header_val_part_find(ctype, ep, "name");
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(pv.key);
  IW_TEST_ASSERT_NSTR_EQUAL(pv.val, "foo.html", 8);

  pv = iwn_wf_header_val_part_find(ctype, ep, "boundary");
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(pv.key);
  IW_TEST_ASSERT_NSTR_EQUAL(pv.val, "zzz", 3);

  // Part iteration
  int parts = 0;
  bool boundary_seen = false;
  struct iwn_pair kv;
  const char *rp = ctype;
  while ((rp = iwn_wf_header_val_part_next(ctype, rp, ep, &kv))) {
    ++parts;
    if (kv.key_len == IW_LLEN("boundary") && strncmp(kv.key, "boundary", kv.key_len) == 0) {
      boundary_seen = true;
      IW_TEST_ASSERT_NSTR_EQUAL(kv.val, "zzz", 3);
    }
  }
  IW_TEST_ASSERT(boundary_seen);
  IW_TEST_ASSERT(parts >= 3);
}

/// Request target/method/headers parsing (`_request_target_parse()`, `_request_method_parse()`,
/// `_request_headers_parse()`) driven through a fake http request.
static void test_request_parsing(void) {
  struct iwpool *pool = 0;

  // Path and query string
  struct request *req = _fake_request(&pool, "/foo/bar?foo=bar&baz=a%40z", "GET");
  IW_TEST_ASSERT_EQUAL_FATAL(dbg_request_parse(req), 0);
  IW_TEST_ASSERT_STR_EQUAL_FATAL(req->base.path, "/foo/bar");
  IW_TEST_ASSERT_EQUAL_FATAL(req->path_len, IW_LLEN("/foo/bar"));
  IW_TEST_ASSERT_EQUAL_FATAL(req->base.flags, IWN_WF_GET);
  IW_TEST_ASSERT_EQUAL_FATAL(_pairs_count(&req->base.query_params), 2);
  dbg_request_destroy(req);

  // Escaped path characters are decoded without changing the path length semantics
  req = _fake_request(&pool, "/%66oo", "GET");
  IW_TEST_ASSERT_EQUAL_FATAL(dbg_request_parse(req), 0);
  IW_TEST_ASSERT_STR_EQUAL_FATAL(req->base.path, "/foo");
  IW_TEST_ASSERT_EQUAL_FATAL(req->path_len, IW_LLEN("/foo"));
  dbg_request_destroy(req);

  // `+` has no special meaning in a path, but is a space in a query string
  req = _fake_request(&pool, "/a+b?c=d+e", "GET");
  IW_TEST_ASSERT_EQUAL_FATAL(dbg_request_parse(req), 0);
  IW_TEST_ASSERT_STR_EQUAL_FATAL(req->base.path, "/a+b");
  IW_TEST_ASSERT_EQUAL_FATAL(req->path_len, IW_LLEN("/a+b"));
  struct iwn_pair *cp = iwn_pair_find(&req->base.query_params, "c", -1);
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(cp);
  IW_TEST_ASSERT_NSTR_EQUAL(cp->val, "d e", 3);
  dbg_request_destroy(req);

  // Truncated/`%25` escapes
  req = _fake_request(&pool, "/100%25?bad=%4", "GET");
  IW_TEST_ASSERT_EQUAL_FATAL(dbg_request_parse(req), 0);
  IW_TEST_ASSERT_STR_EQUAL_FATAL(req->base.path, "/100%");
  IW_TEST_ASSERT_EQUAL_FATAL(req->path_len, IW_LLEN("/100%"));
  cp = iwn_pair_find(&req->base.query_params, "bad", -1);
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(cp);
  IW_TEST_ASSERT_NSTR_EQUAL(cp->val, "%4", 2);
  dbg_request_destroy(req);

  // Supported methods
  struct {
    const char *method;
    uint32_t    flag;
  } methods[] = {
    { "GET", IWN_WF_GET },
    { "PUT", IWN_WF_PUT },
    { "POST", IWN_WF_POST },
    { "HEAD", IWN_WF_HEAD },
    { "DELETE", IWN_WF_DELETE },
    { "OPTIONS", IWN_WF_OPTIONS },
    { "PATCH", IWN_WF_PATCH },
  };
  for (size_t i = 0; i < sizeof(methods) / sizeof(methods[0]); ++i) {
    req = _fake_request(&pool, "/", methods[i].method);
    IW_TEST_ASSERT_EQUAL_FATAL(dbg_request_parse(req), 0);
    IW_TEST_ASSERT_EQUAL_FATAL(req->base.flags, methods[i].flag);
    dbg_request_destroy(req);
  }

  // Unsupported methods of any length
  const char *bad_methods[] = { "TRACE", "XYZ", "GETX", "DELETEX", "CONNECT", 0 };
  for (int i = 0; bad_methods[i]; ++i) {
    req = _fake_request(&pool, "/", bad_methods[i]);
    IW_TEST_ASSERT_EQUAL_FATAL(dbg_request_parse(req), WF_ERROR_UNSUPPORTED_HTTP_METHOD);
    dbg_request_destroy(req);
  }

  // Request form flags
  req = _fake_request(&pool, "/", "POST");
  _fake_header_add(pool, "content-type", "application/x-www-form-urlencoded; charset=utf-8");
  IW_TEST_ASSERT_EQUAL_FATAL(dbg_request_parse(req), 0);
  IW_TEST_ASSERT(req->base.flags & IWN_WF_FORM_URL_ENCODED);
  IW_TEST_ASSERT_FALSE(req->base.flags & IWN_WF_FORM_MULTIPART);
  dbg_request_destroy(req);

  req = _fake_request(&pool, "/", "POST");
  _fake_header_add(pool, "content-type", "multipart/form-data; boundary=xyz");
  IW_TEST_ASSERT_EQUAL_FATAL(dbg_request_parse(req), 0);
  IW_TEST_ASSERT(req->base.flags & IWN_WF_FORM_MULTIPART);
  IW_TEST_ASSERT_STR_EQUAL_FATAL(req->boundary, "xyz");
  dbg_request_destroy(req);

  // Only an exact `boundary` parameter must be accepted
  req = _fake_request(&pool, "/", "POST");
  _fake_header_add(pool, "content-type", "multipart/form-data; boundaryx=bad; boundary=good");
  IW_TEST_ASSERT_EQUAL_FATAL(dbg_request_parse(req), 0);
  IW_TEST_ASSERT_STR_EQUAL_FATAL(req->boundary, "good");
  dbg_request_destroy(req);

  // Multipart content type without a boundary
  req = _fake_request(&pool, "/", "POST");
  _fake_header_add(pool, "content-type", "multipart/form-data");
  IW_TEST_ASSERT_EQUAL_FATAL(dbg_request_parse(req), WF_ERROR_INVALID_FORM_DATA);
  dbg_request_destroy(req);

  // Session cookie
  req = _fake_request(&pool, "/", "GET");
  _fake_header_add(pool, "cookie", "foo=bar; " IWN_WF_SESSION_COOKIE_KEY "=AJyF7R984Ezziz7nYgmezxtxmMbT1Cyr");
  IW_TEST_ASSERT_EQUAL_FATAL(dbg_request_parse(req), 0);
  IW_TEST_ASSERT_STR_EQUAL_FATAL(req->sid, "AJyF7R984Ezziz7nYgmezxtxmMbT1Cyr");
  dbg_request_destroy(req);

  // Session cookie of a wrong length is ignored
  req = _fake_request(&pool, "/", "GET");
  _fake_header_add(pool, "cookie", IWN_WF_SESSION_COOKIE_KEY "=short");
  IW_TEST_ASSERT_EQUAL_FATAL(dbg_request_parse(req), 0);
  IW_TEST_ASSERT_EQUAL_FATAL(req->sid[0], 0);
  dbg_request_destroy(req);

  // Missing request target/method
  req = _fake_request(&pool, "/", "GET");
  _fake_target = (struct iwn_val) {};
  _fake_method = (struct iwn_val) {};
  memset(&_fake_headers, 0, sizeof(_fake_headers));
  IW_TEST_ASSERT_EQUAL_FATAL(dbg_request_parse(req), IW_ERROR_ASSERTION);
  dbg_request_destroy(req);
}

/// Mapping of request creation failures to HTTP response status codes.
static void test_request_error_status(void) {
  IW_TEST_ASSERT_EQUAL_FATAL(dbg_request_error_status(0), 0);
  IW_TEST_ASSERT_EQUAL_FATAL(dbg_request_error_status(IW_ERROR_ASSERTION), 400);
  IW_TEST_ASSERT_EQUAL_FATAL(dbg_request_error_status(WF_ERROR_INVALID_FORM_DATA), 400);
  IW_TEST_ASSERT_EQUAL_FATAL(dbg_request_error_status(WF_ERROR_UNSUPPORTED_HTTP_METHOD), 501);
  IW_TEST_ASSERT_EQUAL_FATAL(dbg_request_error_status(IW_ERROR_ALLOC), 0);
  IW_TEST_ASSERT_EQUAL_FATAL(dbg_request_error_status(IW_ERROR_FAIL), 0);
}

/// A percent-encoded request path must be routed by its decoded value.
static void test_matching_decoded_path(void) {
  iwrc rc = 0;
  RCC(rc, finish, iwn_wf_create(&(struct iwn_wf_route) {
    .handler = _root_handler,
    .tag = "root"
  }, &ctx));

  RCC(rc, finish, iwn_wf_route(&(struct iwn_wf_route) {
    .ctx = ctx,
    .pattern = "/foo/bar",
    .handler = _route_handler,
    .tag = "foobar",
  }, 0));

  struct iwpool *pool = 0;
  struct request *req = _fake_request(&pool, "/foo/%62ar", "GET");
  IW_TEST_ASSERT_EQUAL_FATAL(dbg_request_parse(req), 0);
  struct route_iter it = { 0 };
  dbg_route_iter_init(req, &it);
  struct route *r = dbg_route_iter_next(&it);
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(r);
  IW_TEST_ASSERT_STR_EQUAL_FATAL(r->base.tag, "foobar");
  dbg_request_destroy(req);

finish:
  iwn_wf_destroy(ctx);
  ctx = 0;
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
}

///////////////////////////////////////////////////////////////////////////
//                              Sessions                                  //
///////////////////////////////////////////////////////////////////////////

static const char *_sid1 = "0123456789abcdef0123456789abcdef";
static const char *_sid2 = "abcdef0123456789abcdef0123456789";

/// In-memory session store API (`iwn_wf_sst_inmem.c`).
static void test_session_store(void) {
  iwrc rc = 0;
  struct iwn_wf_session_store sst = { 0 };
  char *val;

  RCC(rc, finish, sst_inmem_create(&sst));
  IW_TEST_ASSERT(sst.get && sst.put && sst.del && sst.clear && sst.dispose);

  RCC(rc, finish, sst.put(&sst, _sid1, "k1", "v1"));
  val = sst.get(&sst, _sid1, "k1");
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(val);
  IW_TEST_ASSERT_STR_EQUAL_FATAL(val, "v1");
  free(val);

  // Overwrite
  RCC(rc, finish, sst.put(&sst, _sid1, "k1", "v2"));
  val = sst.get(&sst, _sid1, "k1");
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(val);
  IW_TEST_ASSERT_STR_EQUAL_FATAL(val, "v2");
  free(val);

  // Sessions are isolated
  RCC(rc, finish, sst.put(&sst, _sid2, "k1", "v3"));
  val = sst.get(&sst, _sid2, "k1");
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(val);
  IW_TEST_ASSERT_STR_EQUAL_FATAL(val, "v3");
  free(val);

  // Absent key/session
  IW_TEST_ASSERT_PTR_NULL_FATAL(sst.get(&sst, _sid1, "absent"));
  IW_TEST_ASSERT_PTR_NULL_FATAL(sst.get(&sst, "absent", "k1"));

  // Delete
  sst.del(&sst, _sid1, "k1");
  IW_TEST_ASSERT_PTR_NULL_FATAL(sst.get(&sst, _sid1, "k1"));
  // Deleting an absent key/session is a no-op
  sst.del(&sst, _sid1, "k1");
  sst.del(&sst, "absent", "k1");

  // Clear wipes all session data
  RCC(rc, finish, sst.put(&sst, _sid1, "a", "1"));
  RCC(rc, finish, sst.put(&sst, _sid1, "b", "2"));
  sst.clear(&sst, _sid1);
  IW_TEST_ASSERT_PTR_NULL_FATAL(sst.get(&sst, _sid1, "a"));
  IW_TEST_ASSERT_PTR_NULL_FATAL(sst.get(&sst, _sid1, "b"));

  // Clearing one session does not touch another one
  RCC(rc, finish, sst.put(&sst, _sid1, "a", "1"));
  sst.clear(&sst, _sid2);
  IW_TEST_ASSERT_PTR_NULL_FATAL(sst.get(&sst, _sid2, "k1"));
  val = sst.get(&sst, _sid1, "a");
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(val);
  free(val);
  sst.clear(&sst, "absent");

finish:
  if (sst.dispose) {
    sst.dispose(&sst);
  }
  IW_TEST_ASSERT_PTR_NULL(sst.user_data);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
}

/// `iwn_wf_session_*` request API on top of the in-memory store.
static void test_session(void) {
  iwrc rc = 0;
  char saved[IWN_WF_SESSION_ID_LEN + 1];
  char *val;

  RCC(rc, finish, iwn_wf_create(&(struct iwn_wf_route) {
    .handler = _root_handler,
    .tag = "root"
  }, &ctx));

  struct ctx *c = (void*) ctx;
  RCC(rc, finish, sst_inmem_create(&c->sst));

  struct iwpool *pool = iwpool_create_empty();
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(pool);
  struct request *req = _request_alloc(pool);

  // No session id, no session data
  IW_TEST_ASSERT_PTR_NULL_FATAL(iwn_wf_session_id(&req->base));
  IW_TEST_ASSERT_PTR_NULL_FATAL(iwn_wf_session_get(&req->base, "k"));

  // Session is created on the first put
  RCC(rc, finish, iwn_wf_session_put(&req->base, "k", "v"));
  const char *sid = iwn_wf_session_id(&req->base);
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(sid);
  IW_TEST_ASSERT_EQUAL_FATAL(strlen(sid), IWN_WF_SESSION_ID_LEN);
  IW_TEST_ASSERT_STR_EQUAL_FATAL(iwn_wf_session_get(&req->base, "k"), "v");

  // printf formatted value
  RCC(rc, finish, iwn_wf_session_printf(&req->base, "n", "%d-%s", 42, "x"));
  IW_TEST_ASSERT_STR_EQUAL_FATAL(iwn_wf_session_get(&req->base, "n"), "42-x");

  // The store holds the session data
  memcpy(saved, sid, sizeof(saved));
  val = c->sst.get(&c->sst, saved, "k");
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(val);
  IW_TEST_ASSERT_STR_EQUAL_FATAL(val, "v");
  free(val);

  // Delete a key
  iwn_wf_session_del(&req->base, "k");
  IW_TEST_ASSERT_PTR_NULL_FATAL(iwn_wf_session_get(&req->base, "k"));

  // NULL data deletes the key
  RCC(rc, finish, iwn_wf_session_put(&req->base, "k", "v2"));
  RCC(rc, finish, iwn_wf_session_put(&req->base, "k", 0));
  IW_TEST_ASSERT_PTR_NULL_FATAL(iwn_wf_session_get(&req->base, "k"));

  // Clear drops the session id and all stored data
  RCC(rc, finish, iwn_wf_session_put(&req->base, "x", "y"));
  iwn_wf_session_clear(&req->base);
  IW_TEST_ASSERT_PTR_NULL_FATAL(iwn_wf_session_id(&req->base));
  IW_TEST_ASSERT_PTR_NULL_FATAL(iwn_wf_session_get(&req->base, "x"));
  val = c->sst.get(&c->sst, saved, "x");
  IW_TEST_ASSERT_PTR_NULL_FATAL(val);

  // Attach an existing session id
  IW_TEST_ASSERT_EQUAL_FATAL(iwn_wf_session_id_set(&req->base, 0), IW_ERROR_INVALID_ARGS);
  IW_TEST_ASSERT_EQUAL_FATAL(iwn_wf_session_id_set(&req->base, "short"), IW_ERROR_INVALID_ARGS);
  RCC(rc, finish, c->sst.put(&c->sst, saved, "k2", "v4"));
  RCC(rc, finish, iwn_wf_session_id_set(&req->base, saved));
  IW_TEST_ASSERT_STR_EQUAL_FATAL(iwn_wf_session_id(&req->base), saved);
  IW_TEST_ASSERT_STR_EQUAL_FATAL(iwn_wf_session_get(&req->base, "k2"), "v4");

  // Switching the session id invalidates the cached values
  RCC(rc, finish, iwn_wf_session_id_set(&req->base, _sid2));
  IW_TEST_ASSERT_PTR_NULL_FATAL(iwn_wf_session_get(&req->base, "k2"));

  dbg_request_destroy(req);

finish:
  iwn_wf_destroy(ctx);
  ctx = 0;
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
}

///////////////////////////////////////////////////////////////////////////
//                               Multipart                                //
///////////////////////////////////////////////////////////////////////////

static bool _ensure_multipart(
  struct iwn_pairs *parts,
  const char       *name,
  const char       *file,
  const char       *ctype,
  const char       *data) {
  IW_TEST_ASSERT_FATAL(parts && name);
  struct iwn_pair *part = iwn_pair_find(parts, name, -1), *p = 0;
  if (!part) {
    return false;
  }
  if (file) {
    p = iwn_pair_find(part->extra, "filename", IW_LLEN("filename"));
    if (!p || strncmp(p->val, file, p->val_len) != 0) {
      return false;
    }
  }
  if (ctype) {
    p = iwn_pair_find(part->extra, "content-type", IW_LLEN("content-type"));
    if (!p || strncmp(p->val, ctype, p->val_len) != 0) {
      return false;
    }
  }
  if (data) {
    if ((file || ctype) && !p) {
      return false;
    }
    if (strncmp(part->val, data, part->val_len) != 0) {
      return false;
    }
  }
  return true;
}

static void _multipart_parsing3(struct iwpool *pool) {
  char *rp
    = strdup("--x\r\n"
             "Content-Disposition: inline; name=\"zz\"\r\n"
             "\r\nz\r\n"
             "--x--\r\n");

  bool eof = false;
  struct iwn_pairs parts = { 0 };
  const char *ep = rp + strlen(rp);
  const char *cp = dbg_multipart_parse_next(pool, "x", 1, rp, ep, &parts, &eof);
  IW_TEST_ASSERT(!cp);
  IW_TEST_ASSERT(!eof);

  memset(&parts, 0, sizeof(parts));
  free(rp);
  rp
    = strdup("--x\r\n"
             "Content-Disposition: form-data; name=\"zz\"\r\n"
             "\r\nz\r\n"
             "--x--\r\n");
  ep = rp + strlen(rp);
  cp = dbg_multipart_parse_next(pool, "x", 1, rp, ep, &parts, &eof);
  IW_TEST_ASSERT(cp);
  IW_TEST_ASSERT(!eof);

  memset(&parts, 0, sizeof(parts));
  free(rp);
  rp
    = strdup("--x\r\n"
             "Content-Disposition: form-data; name=\"zz\"; filename=\"f\\oo.html\"\r\n"
             "\r\nz\r\n"
             "--x--\r\n");
  ep = rp + strlen(rp);
  cp = dbg_multipart_parse_next(pool, "x", 1, rp, ep, &parts, &eof);
  IW_TEST_ASSERT(_ensure_multipart(&parts, "zz", "foo.html", 0, 0));
  IW_TEST_ASSERT(cp);
  IW_TEST_ASSERT(!eof);

  memset(&parts, 0, sizeof(parts));
  free(rp);
  rp
    = strdup("--x\r\n"
             "Content-Disposition: form-data; name=z,z\r\n"
             "\r\nz\r\n"
             "--x--\r\n");
  ep = rp + strlen(rp);
  cp = dbg_multipart_parse_next(pool, "x", 1, rp, ep, &parts, &eof);
  // TODO: should be cp == 0
  // http://test.greenbytes.de/tech/tc2231/#attwithtokfncommanq
  IW_TEST_ASSERT(cp);
  IW_TEST_ASSERT(!eof);

  memset(&parts, 0, sizeof(parts));
  free(rp);
  rp
    = strdup("--x\r\n"
             "Content-Disposition: form-data; name=z"
             "\r\nz\r\n"
             "--x--\r\n");
  ep = rp + strlen(rp);
  cp = dbg_multipart_parse_next(pool, "x", 1, rp, ep, &parts, &eof);
  IW_TEST_ASSERT(!cp);
  IW_TEST_ASSERT(!eof);

  memset(&parts, 0, sizeof(parts));
  free(rp);
  rp
    = strdup("--x\r\n"
             "Content-Disposition: form-data; name=\"zz\"\r\n"
             "\r\nz\r\n"
             "--xx--\r\n");
  ep = rp + strlen(rp);
  cp = dbg_multipart_parse_next(pool, "x", 1, rp, ep, &parts, &eof);
  IW_TEST_ASSERT(!cp);
  IW_TEST_ASSERT(!eof);

  memset(&parts, 0, sizeof(parts));
  free(rp);
  rp
    = strdup("--x\r\n"
             "Content-Disposition: form-data; name=\"zz\";\r\n"
             "\r\nz\r\n"
             "--x--\r\n");
  ep = rp + strlen(rp);
  cp = dbg_multipart_parse_next(pool, "x", 1, rp, ep, &parts, &eof);
  IW_TEST_ASSERT(cp);
  IW_TEST_ASSERT(!eof);

  memset(&parts, 0, sizeof(parts));
  free(rp);
  rp
    = strdup("--x\r\n"
             "Content-Disposition: form-data; name=\"a\"; filename=foo[1](2).html\r\n"
             "\r\nz\r\n"
             "--x--\r\n");
  ep = rp + strlen(rp);
  cp = dbg_multipart_parse_next(pool, "x", 1, rp, ep, &parts, &eof);
  IW_TEST_ASSERT(!cp);
  IW_TEST_ASSERT(!eof);

  memset(&parts, 0, sizeof(parts));
  free(rp);
  rp
    = strdup("--x\r\n"
             "Content-Disposition: form-data; filename=\"zz\"\r\n"
             "\r\nz\r\n"
             "--x--\r\n");
  ep = rp + strlen(rp);
  cp = dbg_multipart_parse_next(pool, "x", 1, rp, ep, &parts, &eof);
  IW_TEST_ASSERT(!cp);
  IW_TEST_ASSERT(!eof);

  memset(&parts, 0, sizeof(parts));
  free(rp);
  rp
    = strdup("--x\r\n"
             "Content-Disposition: \"kk\"; name=\"zz\"\r\n"
             "\r\nz\r\n"
             "--x--\r\n");
  ep = rp + strlen(rp);
  cp = dbg_multipart_parse_next(pool, "x", 1, rp, ep, &parts, &eof);
  IW_TEST_ASSERT(!cp);
  IW_TEST_ASSERT(!eof);
  free(rp);
}

static void _multipart_parsing2(struct iwpool *pool) {
  char *rp
    = strdup("--\r\n"
             "Content-Disposition: form-data; name=\"\"\r\n"
             "Content-Type: \r\n"
             "\r\n[DATA]\r\n"
             "----\r\n");

  bool eof = false;
  struct iwn_pairs parts = { 0 };
  const char *ep = rp + strlen(rp);
  const char *cp = dbg_multipart_parse_next(pool, "", 0, rp, ep, &parts, &eof);
  IW_TEST_ASSERT_FATAL(cp);
  IW_TEST_ASSERT(!eof);
  IW_TEST_ASSERT(_ensure_multipart(&parts, "", 0, 0, 0));
  cp = dbg_multipart_parse_next(pool, "", 0, cp, ep, &parts, &eof);
  IW_TEST_ASSERT(!cp);
  IW_TEST_ASSERT(eof);
  free(rp);
}

static void _multipart_parsing1(struct iwpool *pool) {
  char *rp
    = strdup("--xyz\r\n"
             "Content-Disposition: form-data; name=\"name\"\r\n"
             "Content-Type: text/plain;charset=UTF-8\r\n"
             "\r\nJohn\r\n"
             "--xyz\r\n"
             "Content-Disposition:form-data; name=\"age\"\r\n"
             "\r\n23\r\n"
             "--xyz\r\n"
             "Content-Disposition: form-data; name=\"photo\"; filename=\"photo.jpeg\"\r\n"
             "Content-TYPE: image/jpeg\r\n"
             "\r\nxxJPGxx\r\n"
             "--xyz--\r\n");

  bool eof = false;
  struct iwn_pairs parts = { 0 };
  const char *ep = rp + strlen(rp);
  const char *cp = dbg_multipart_parse_next(pool, "xyz", IW_LLEN("xyz"), rp, ep, &parts, &eof);
  IW_TEST_ASSERT_FATAL(cp);
  IW_TEST_ASSERT(!eof);
  IW_TEST_ASSERT(_ensure_multipart(&parts, "name", 0, "text/plain;charset=UTF-8", "John"));

  cp = dbg_multipart_parse_next(pool, "xyz", IW_LLEN("xyz"), cp, ep, &parts, &eof);
  IW_TEST_ASSERT_FATAL(cp);
  IW_TEST_ASSERT(!eof);
  IW_TEST_ASSERT(_ensure_multipart(&parts, "age", 0, 0, "23"));

  cp = dbg_multipart_parse_next(pool, "xyz", IW_LLEN("xyz"), cp, ep, &parts, &eof);
  IW_TEST_ASSERT_FATAL(cp);
  IW_TEST_ASSERT(!eof);
  IW_TEST_ASSERT(_ensure_multipart(&parts, "photo", "photo.jpeg", "image/jpeg", "xxJPGxx"));

  cp = dbg_multipart_parse_next(pool, "xyz", IW_LLEN("xyz"), cp, ep, &parts, &eof);
  IW_TEST_ASSERT(!cp);
  IW_TEST_ASSERT(eof);
  free(rp);
}

static void test_multipart_parsing(void) {
  struct iwpool *pool = iwpool_create_empty();
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(pool);
  _multipart_parsing1(pool);
  _multipart_parsing2(pool);
  _multipart_parsing3(pool);
  iwpool_destroy(pool);
}

int main(int argc, char *argv[]) {
  static const struct iw_test_case cases[] = {
    IW_TEST_CASE(test_simple_matching),
    IW_TEST_CASE(test_regexp_matching),
    IW_TEST_CASE(test_prefix_matching),
    IW_TEST_CASE(test_route_errors),
    IW_TEST_CASE(test_route_print),
    IW_TEST_CASE(test_regexp_submatches),
    IW_TEST_CASE(test_query_parsing),
    IW_TEST_CASE(test_header_parsing),
    IW_TEST_CASE(test_request_parsing),
    IW_TEST_CASE(test_request_error_status),
    IW_TEST_CASE(test_matching_decoded_path),
    IW_TEST_CASE(test_session_store),
    IW_TEST_CASE(test_session),
    IW_TEST_CASE(test_multipart_parsing),
  };
  return iw_test_run(argc, argv, IW_TEST_SUITE("http_wf", cases, 0, 0));
}

#include "iwn_tests.h"
#include "iwn_wf_internal.h"
#include "iwn_codec.h"

#include <string.h>

static struct iwn_wf_ctx *ctx;

static int _root_handler(struct iwn_wf_req *req, void *user_data) {
  return 0;
}

static int _route_handler(struct iwn_wf_req *req, void *user_data) {
  return 0;
}

static struct request* _request_create(const char *path, int method, struct iwpool *pool) {
  struct request *req = iwpool_calloc(sizeof(*req), pool);
  IWN_ASSERT_FATAL(req);
  req->base.path = path;
  req->path_len = strlen(path);
  req->base.path_unmatched = path;
  req->base.ctx = ctx;
  req->base.flags = method;
  req->pool = pool;
  return req;
}

static struct route* _request_first_matched(const char *path, int methods, struct route_iter *oit) {
  struct iwpool *pool = iwpool_create_empty();
  IWN_ASSERT_FATAL(pool);
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

static iwrc test_regexp_matching(void) {
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
  IWN_ASSERT(r);
  dbg_request_destroy(it.req);

finish:
  iwn_wf_destroy(ctx);
  ctx = 0;
  return rc;
}

static iwrc test_header_parsing(void) {
  iwrc rc = 0;
  const char *rp = "_ga=GA1.2.258852180.1582174090; sessionid=AJyF7R984Ezziz7nYgmezxtxmMbT1Cyr\r\nU";
  const char *ep = strchr(rp, '\r');
  IWN_ASSERT_FATAL(ep);
  struct iwn_pair pv = iwn_wf_header_val_part_find(rp, ep, "sessionid");

  return rc;
}

static iwrc test_simple_matching(void) {
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
  IWN_ASSERT(r);
  if (r) {
    IWN_ASSERT(strcmp(r->pattern, "/bar") == 0);
  }
  dbg_request_destroy(it.req);

  r = _request_first_matched("/bar", IWN_WF_POST, &it);
  IWN_ASSERT(!rc);
  dbg_request_destroy(it.req);

  r = _request_first_matched("/foo", IWN_WF_GET, &it);
  IWN_ASSERT(r);
  if (r) {
    IWN_ASSERT(strcmp(r->pattern, "/foo") == 0);
  }
  r = dbg_route_iter_next(&it);
  IWN_ASSERT(!r);
  dbg_request_destroy(it.req);

  r = _request_first_matched("/foo/bar", IWN_WF_GET, &it);
  IWN_ASSERT_FATAL(r);
  IWN_ASSERT_FATAL(strcmp(r->pattern, "/foo") == 0);

  r2 = dbg_route_iter_next(&it);
  IWN_ASSERT_FATAL(r2);
  IWN_ASSERT(r2->parent == r);
  IWN_ASSERT_FATAL(strcmp(r2->pattern, "/bar") == 0);

  r = dbg_route_iter_next(&it);
  IWN_ASSERT_FATAL(r);
  IWN_ASSERT(r->parent == r2);
  IWN_ASSERT(strcmp(r->base.tag, "bar2_nested") == 0);
  dbg_request_destroy(it.req);

finish:
  iwn_wf_destroy(ctx);
  ctx = 0;
  return rc;
}

static bool _ensure_multipart(
  struct iwn_pairs *parts,
  const char       *name,
  const char       *file,
  const char       *ctype,
  const char       *data) {
  IWN_ASSERT_FATAL(parts && name);
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
  IWN_ASSERT(!cp);
  IWN_ASSERT(!eof);

  memset(&parts, 0, sizeof(parts));
  free(rp);
  rp
    = strdup("--x\r\n"
             "Content-Disposition: form-data; name=\"zz\"\r\n"
             "\r\nz\r\n"
             "--x--\r\n");
  ep = rp + strlen(rp);
  cp = dbg_multipart_parse_next(pool, "x", 1, rp, ep, &parts, &eof);
  IWN_ASSERT(cp);
  IWN_ASSERT(!eof);

  memset(&parts, 0, sizeof(parts));
  free(rp);
  rp
    = strdup("--x\r\n"
             "Content-Disposition: form-data; name=\"zz\"; filename=\"f\\oo.html\"\r\n"
             "\r\nz\r\n"
             "--x--\r\n");
  ep = rp + strlen(rp);
  cp = dbg_multipart_parse_next(pool, "x", 1, rp, ep, &parts, &eof);
  IWN_ASSERT(_ensure_multipart(&parts, "zz", "foo.html", 0, 0));
  IWN_ASSERT(cp);
  IWN_ASSERT(!eof);

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
  IWN_ASSERT(cp);
  IWN_ASSERT(!eof);

  memset(&parts, 0, sizeof(parts));
  free(rp);
  rp
    = strdup("--x\r\n"
             "Content-Disposition: form-data; name=z"
             "\r\nz\r\n"
             "--x--\r\n");
  ep = rp + strlen(rp);
  cp = dbg_multipart_parse_next(pool, "x", 1, rp, ep, &parts, &eof);
  IWN_ASSERT(!cp);
  IWN_ASSERT(!eof);

  memset(&parts, 0, sizeof(parts));
  free(rp);
  rp
    = strdup("--x\r\n"
             "Content-Disposition: form-data; name=\"zz\"\r\n"
             "\r\nz\r\n"
             "--xx--\r\n");
  ep = rp + strlen(rp);
  cp = dbg_multipart_parse_next(pool, "x", 1, rp, ep, &parts, &eof);
  IWN_ASSERT(!cp);
  IWN_ASSERT(!eof);

  memset(&parts, 0, sizeof(parts));
  free(rp);
  rp
    = strdup("--x\r\n"
             "Content-Disposition: form-data; name=\"zz\";\r\n"
             "\r\nz\r\n"
             "--x--\r\n");
  ep = rp + strlen(rp);
  cp = dbg_multipart_parse_next(pool, "x", 1, rp, ep, &parts, &eof);
  IWN_ASSERT(cp);
  IWN_ASSERT(!eof);

  memset(&parts, 0, sizeof(parts));
  free(rp);
  rp
    = strdup("--x\r\n"
             "Content-Disposition: form-data; name=\"a\"; filename=foo[1](2).html\r\n"
             "\r\nz\r\n"
             "--x--\r\n");
  ep = rp + strlen(rp);
  cp = dbg_multipart_parse_next(pool, "x", 1, rp, ep, &parts, &eof);
  IWN_ASSERT(!cp);
  IWN_ASSERT(!eof);

  memset(&parts, 0, sizeof(parts));
  free(rp);
  rp
    = strdup("--x\r\n"
             "Content-Disposition: form-data; filename=\"zz\"\r\n"
             "\r\nz\r\n"
             "--x--\r\n");
  ep = rp + strlen(rp);
  cp = dbg_multipart_parse_next(pool, "x", 1, rp, ep, &parts, &eof);
  IWN_ASSERT(!cp);
  IWN_ASSERT(!eof);

  memset(&parts, 0, sizeof(parts));
  free(rp);
  rp
    = strdup("--x\r\n"
             "Content-Disposition: \"kk\"; name=\"zz\"\r\n"
             "\r\nz\r\n"
             "--x--\r\n");
  ep = rp + strlen(rp);
  cp = dbg_multipart_parse_next(pool, "x", 1, rp, ep, &parts, &eof);
  IWN_ASSERT(!cp);
  IWN_ASSERT(!eof);
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
  IWN_ASSERT_FATAL(cp);
  IWN_ASSERT(!eof);
  IWN_ASSERT(_ensure_multipart(&parts, "", 0, 0, 0));
  cp = dbg_multipart_parse_next(pool, "", 0, cp, ep, &parts, &eof);
  IWN_ASSERT(!cp);
  IWN_ASSERT(eof);
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
  IWN_ASSERT_FATAL(cp);
  IWN_ASSERT(!eof);
  IWN_ASSERT(_ensure_multipart(&parts, "name", 0, "text/plain;charset=UTF-8", "John"));

  cp = dbg_multipart_parse_next(pool, "xyz", IW_LLEN("xyz"), cp, ep, &parts, &eof);
  IWN_ASSERT_FATAL(cp);
  IWN_ASSERT(!eof);
  IWN_ASSERT(_ensure_multipart(&parts, "age", 0, 0, "23"));

  cp = dbg_multipart_parse_next(pool, "xyz", IW_LLEN("xyz"), cp, ep, &parts, &eof);
  IWN_ASSERT_FATAL(cp);
  IWN_ASSERT(!eof);
  IWN_ASSERT(_ensure_multipart(&parts, "photo", "photo.jpeg", "image/jpeg", "xxJPGxx"));

  cp = dbg_multipart_parse_next(pool, "xyz", IW_LLEN("xyz"), cp, ep, &parts, &eof);
  IWN_ASSERT(!cp);
  IWN_ASSERT(eof);
  free(rp);
}

static iwrc test_multipart_parsing(void) {
  iwrc rc = 0;
  struct iwpool *pool = iwpool_create_empty();
  IWN_ASSERT_FATAL(pool);
  _multipart_parsing1(pool);
  _multipart_parsing2(pool);
  _multipart_parsing3(pool);
  iwpool_destroy(pool);
  return rc;
}

int main(int argc, char *argv[]) {
  iwrc rc = 0;
  //RCC(rc, finish, test_header_parsing());
  RCC(rc, finish, test_simple_matching());
  RCC(rc, finish, test_regexp_matching());
  RCC(rc, finish, test_multipart_parsing());
finish:
  IWN_ASSERT(rc == 0);
  return iwn_assertions_failed > 0 ? 1 : 0;
}

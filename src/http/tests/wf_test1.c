#include "utils/tests.h"
#include "wf_internal.h"

#include <string.h>

static struct iwn_wf_ctx *ctx;

static int _root_handler(struct iwn_wf_req *req) {
  return -1;
}

static int _route_handler(struct iwn_wf_req *req) {
  return -1;
}

static struct request* _request_create(const char *path, int method, IWPOOL *pool) {
  struct request *req = iwpool_calloc(sizeof(*req), pool);
  IWN_ASSERT_FATAL(req);
  req->base.path = path;
  req->base.path_unmatched = path;
  req->base.ctx = ctx;
  req->base.method = method;
  req->pool = pool;
  return req;
}

static struct route* _request_first_matched(const char *path, int methods, struct route_iter *oit) {
  IWPOOL *pool = iwpool_create_empty();
  IWN_ASSERT_FATAL(pool);
  struct request *req = _request_create(path, methods, pool);
  struct route_iter it = { 0 };
  route_iter_init(req, &it);
  struct route *route = route_iter_next(&it);
  if (oit) {
    memcpy(oit, &it, sizeof(*oit));
  } else {
    request_destroy(req);
  }
  return route;
}

static iwrc test_matching1(void) {
  iwrc rc = 0;
  struct route_iter it = { 0 };
  struct route *r, *r2;
  struct iwn_wf_route *p, *p2;

  RCC(rc, finish, iwn_wf_create(&(struct iwn_wf_route) {
    .handler = _root_handler,
    .tag = "root"
  }, &ctx));

  RCC(rc, finish, iwn_wf_route_create(&(struct iwn_wf_route) {
    .ctx = ctx,
    .pattern = "/foo",
    .handler = _route_handler,
  }, &p));

  RCC(rc, finish, iwn_wf_route_create(&(struct iwn_wf_route) {
    .ctx = ctx,
    .pattern = "/bar",
    .flags = IWN_WF_GET | IWN_WF_PUT,
    .handler = _route_handler,
    .tag = "bar0",
  }, 0));


  RCC(rc, finish, iwn_wf_route_create(&(struct iwn_wf_route) {
    .parent = p,
    .pattern = "/zaz",
    .handler = _route_handler,
  }, 0));

  RCC(rc, finish, iwn_wf_route_create(&(struct iwn_wf_route) {
    .parent = p,
    .pattern = "/bar",
    .handler = _route_handler,
    .tag = "bar2"
  }, &p2));

  RCC(rc, finish, iwn_wf_route_create(&(struct iwn_wf_route) {
    .parent = p2,
    .handler = _route_handler,
    .tag = "bar2_nested"
  }, 0));

  r = _request_first_matched("/bar", IWN_WF_PUT, &it);
  IWN_ASSERT(r);
  if (r) {
    IWN_ASSERT(strcmp(r->pattern, "/bar") == 0);
  }
  request_destroy(it.req);

  r = _request_first_matched("/bar", IWN_WF_POST, &it);
  IWN_ASSERT(!rc);
  request_destroy(it.req);

  r = _request_first_matched("/foo", IWN_WF_GET, &it);
  IWN_ASSERT(r);
  if (r) {
    IWN_ASSERT(strcmp(r->pattern, "/foo") == 0);
  }
  r = route_iter_next(&it);
  IWN_ASSERT(!r);
  request_destroy(it.req);

  r = _request_first_matched("/foo/bar", IWN_WF_GET, &it);
  IWN_ASSERT_FATAL(r);
  IWN_ASSERT_FATAL(strcmp(r->pattern, "/foo") == 0);

  r2 = route_iter_next(&it);
  IWN_ASSERT_FATAL(r2);
  IWN_ASSERT(r2->parent == r);
  IWN_ASSERT_FATAL(strcmp(r2->pattern, "/bar") == 0);

  r = route_iter_next(&it);
  IWN_ASSERT_FATAL(r);
  IWN_ASSERT(r->parent == r2);
  IWN_ASSERT(strcmp(r->base.tag, "bar2_nested") == 0);
  request_destroy(it.req);

finish:
  iwn_wf_destroy(ctx);
  ctx = 0;
  return rc;
}

int main(int argc, char *argv[]) {
  iwrc rc = 0;
  RCC(rc, finish, test_matching1());
finish:
  IWN_ASSERT(rc == 0);
  return iwn_asserts_failed > 0 ? 1 : 0;
}

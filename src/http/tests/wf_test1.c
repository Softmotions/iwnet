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
  it.req = req;
  route_iter_init(req, &it);
  struct route *route = route_iter_next(req, &it);
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

  RCC(rc, finish, iwn_wf_create(&(struct iwn_wf_route) {
    .handler = _root_handler,
    .tag = "root"
  }, &ctx));

  RCC(rc, finish, iwn_wf_route_create(&(struct iwn_wf_route) {
    .ctx = ctx,
    .pattern = "/foo",
    .flags = IWN_WF_FLAG_MATCH_END,
    .handler = _route_handler,
  }, 0));

  RCC(rc, finish, iwn_wf_route_create(&(struct iwn_wf_route) {
    .ctx = ctx,
    .pattern = "/bar",
    .flags = IWN_WF_GET | IWN_WF_PUT,
    .handler = _route_handler,
  }, 0));

  RCC(rc, finish, iwn_wf_route_create(&(struct iwn_wf_route) {
    .ctx = ctx,
    .pattern = "/foo/bar",
    .handler = _route_handler,
  }, 0));

  struct route *r = _request_first_matched("/foo", IWN_WF_GET, &it);
  IWN_ASSERT(r);
  if (r) {
    IWN_ASSERT(strcmp(r->pattern, "/foo") == 0);
  }
  request_destroy(it.req);

  // r = _request_first_matched("")


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

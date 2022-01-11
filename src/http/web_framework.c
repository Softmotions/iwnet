#include "web_framework.h"

#include <iowow/iwlog.h>
#include <iowow/iwpool.h>
#include <iowow/iwre.h>


#include <errno.h>
#include <string.h>
#include <stdbool.h>

struct route;

struct ctx {
  // iwn_wf_ctx fields
  struct iwn_http_server_spec http;
  void *user_data;
  // EOF iwn_wf_ctx fields
  IWPOOL       *pool;
  struct route *root;
  iwn_wf_on_ctx_dispose on_ctx_dispose;
};

struct route {
  struct ctx    *ctx;
  struct route  *parent;
  struct route  *child;
  struct route  *next;
  const char    *pattern;
  const char    *tag;
  iwn_wf_handler handler;
  iwn_wf_handler_dispose handler_dispose;
  void    *handler_data;
  uint32_t flags;
};

static const char* _ecodefn(locale_t, uint32_t);

IW_INLINE iwrc _init(void) {
  static bool _initialized;

  if (__sync_bool_compare_and_swap(&_initialized, false, true)) {
    RCR(iwlog_register_ecodefn(_ecodefn));
  }
  return 0;
}

static bool _request_handler(struct iwn_http_request *req) {
  // TODO:
  return true;
}

static void _ctx_destroy(struct ctx *ctx) {
  if (!ctx) {
    return;
  }
  if (ctx->on_ctx_dispose) {
    ctx->on_ctx_dispose((void*) ctx);
  }
  iwpool_destroy(ctx->pool);
}

static void _on_server_dispose(const struct iwn_http_server *server) {
  struct ctx *ctx = server->user_data;

  if (ctx) {
    _ctx_destroy(ctx);
  }
}

static iwrc _route_pattern_check(const char *pattern) {
  if (!pattern) {
    return 0;
  }
  // TODO:
  return 0;
}

//static void _route_add()

iwrc iwn_wf_route(
  struct iwn_wf_ctx     *ctx_,
  iwn_wf_route_t         parent_,
  const char            *pattern,
  uint32_t               flags,
  iwn_wf_handler         handler,
  iwn_wf_handler_dispose handler_dispose,
  void                  *handler_data,
  iwn_wf_route_t        *out_route,
  const char            *tag
  ) {
  if (out_route) {
    *out_route = 0;
  }
  if (!ctx_) {
    return IW_ERROR_INVALID_ARGS;
  }
  if (parent_ && ((struct route*) parent_)->ctx != (void*) ctx_) {
    return WF_ERROR_PARENT_ROUTE_FROM_DIFFERENT_CONTEXT;
  }

  iwrc rc = 0;
  struct ctx *ctx = (void*) ctx_;
  IWPOOL *pool = ctx->pool;
  struct route *route = 0, *parent = parent_;

  if (!ctx->root) {
    RCA(ctx->root = iwpool_calloc(sizeof(*ctx->root), pool), finish);
    ctx->root->ctx = ctx;
    ctx->root->tag = "root";
  }
  if (!parent) {
    parent = ctx->root;
  }

  RCA(route = iwpool_calloc(sizeof(*route), pool), finish);
  if (pattern) {
    RCA(route->pattern = iwpool_strdup2(pool, pattern), finish);
  }
  if (tag) {
    RCA(route->tag = iwpool_strdup2(pool, tag), finish);
  }
  route->ctx = ctx;
  route->flags = flags;
  route->handler = handler;
  route->handler_dispose = handler_dispose;
  route->handler_data = handler_data;

finish:
  if (!rc) {
    if (out_route) {
      *out_route = route;
    }
  }
  return rc;
}

iwrc iwn_wf_create(
  const struct iwn_http_server_spec *http_,
  iwn_wf_on_ctx_dispose              on_ctx_dispose,
  struct iwn_wf_ctx                **out_ctx
  ) {
  RCR(_init());
  iwrc rc = 0;
  struct ctx *ctx = 0;
  struct iwn_http_server_spec http = { 0 };
  IWPOOL *pool = iwpool_create_empty();

  if (!pool) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  RCA(ctx = iwpool_calloc(sizeof(*ctx), pool), finish);
  ctx->user_data = http_->user_data;
  ctx->on_ctx_dispose = on_ctx_dispose;

  memcpy(&http, http_, sizeof(http));
  http.user_data = ctx;
  http.request_handler = _request_handler;

finish:
  if (rc) {
    if (ctx) {
      _ctx_destroy(ctx);
    } else {
      iwpool_destroy(pool);
    }
  }
  return rc;
}

void iwn_wf_destroy(struct iwn_wf_ctx *ctx) {
  _ctx_destroy((void*) ctx);
}

static const char* _ecodefn(locale_t locale, uint32_t ecode) {
  if (ecode <= _WF_ERROR_START || ecode >= _WF_ERROR_END) {
    return 0;
  }
  switch (ecode) {
    case WF_ERROR_INVALID_FORM_DATA:
      return "Invalid (unparseable) form data (WF_ERROR_INVALID_FORM_DATA).";
    case WF_ERROR_PARENT_ROUTE_FROM_DIFFERENT_CONTEXT:
      return "Parent router from different context (WF_ERROR_PARENT_ROUTER_FROM_DIFFERENT_CONTEXT).";
    case WF_ERROR_INVALID_ROUTE_PATTERN:
      return "Invalid route pattern (WF_ERROR_INVALID_ROUTE_PATTERN).";
  }
  return 0;
}

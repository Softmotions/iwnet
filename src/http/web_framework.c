#include "web_framework.h"

#include <iowow/iwlog.h>
#include <iowow/iwpool.h>
#include <iowow/iwre.h>

#include <errno.h>
#include <string.h>
#include <stdbool.h>

struct ctx {
  struct iwn_wf_ctx    base;
  struct iwn_wf_route *root;
  IWPOOL *pool;
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


static void _on_server_dispose(const struct iwn_http_server *server) {
  struct ctx *ctx = server->user_data;
  if (ctx) {
    
  }
}

static iwrc _route_pattern_check(const char *pattern) {
  if (!pattern) {
    return 0;
  }
  // TODO:
  return 0;
}

static void _route_add(struct iwn_wf_route *parent, struct iwn_wf_route *route) {
  route->next = route->child = 0;
  route->parent = parent;
  struct iwn_wf_route *r = parent->child;
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

static iwrc _route_import(const struct iwn_wf_route *spec, struct ctx *ctx, struct iwn_wf_route **out) {
  *out = 0;
  iwrc rc = 0;
  struct iwn_wf_route *route;
  IWPOOL *pool = ctx->pool;

  if (spec->parent && spec->parent->ctx != &ctx->base) {
    return WF_ERROR_PARENT_ROUTE_FROM_DIFFERENT_CONTEXT;
  }

  RCR(_route_pattern_check(spec->pattern));
  RCA(route = iwpool_alloc(sizeof(*route), pool), finish);
  memcpy(route, spec, sizeof(*route));
  if (spec->pattern) {
    RCA(route->pattern = iwpool_strdup2(pool, spec->pattern), finish);
  }
  if (spec->tag) {
    RCA(route->tag = iwpool_strdup2(pool, spec->tag), finish);
  }
  if (route->parent) {
    _route_add(route->parent, route);
  }

finish:
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
  RCC(rc, finish, _route_import(root_route_spec, ctx, &ctx->root));
  ctx->base.root_route = ctx->root;

finish:
  if (rc) {
    iwpool_destroy(pool);
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

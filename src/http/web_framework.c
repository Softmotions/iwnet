#include "web_framework.h"

#include <iowow/iwlog.h>
#include <iowow/iwpool.h>
#include <iowow/iwre.h>

#include <errno.h>
#include <string.h>
#include <stdbool.h>
#include <pthread.h>

struct route;

struct ctx {
  struct iwn_wf_ctx  base;
  struct route      *root;
  struct iwn_poller *poller;
  IWPOOL *pool;
  int     server_fd;
  int     request_file_max_size;
};

#define ROUTE_FLG_RE_MATCH_END 0x01

struct route {
  struct iwn_wf_route base;
  struct route       *parent;
  struct route       *child;
  struct route       *next;
  pthread_mutex_t     mtx;
  char      *pattern;
  struct re *pattern_re;
  uint32_t   re_flags;
};

static const char* _ecodefn(locale_t, uint32_t);

IW_INLINE iwrc _init(void) {
  static bool _initialized;
  if (__sync_bool_compare_and_swap(&_initialized, false, true)) {
    RCR(iwlog_register_ecodefn(_ecodefn));
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
    handler_dispose(base->ctx, base->handler_data);
  }
  route->pattern = 0;
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
  if (len) {
    if (*pattern == '^') { // We use regexp
      if (pattern[len - 1] == '$') {
        route->re_flags |= ROUTE_FLG_RE_MATCH_END;
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
  struct route *route;
  struct iwn_wf_route *base;
  IWPOOL *pool = ctx->pool;

  if (spec->parent && spec->parent->ctx != &ctx->base) {
    return WF_ERROR_PARENT_ROUTE_FROM_DIFFERENT_CONTEXT;
  }

  RCA(route = iwpool_calloc(sizeof(*route), pool), finish);
  memcpy(&route->mtx, &(pthread_mutex_t) PTHREAD_MUTEX_INITIALIZER, sizeof(route->mtx));
  memcpy(&route->base, spec, sizeof(*route));
  base = &route->base;

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

static bool _request_handler(struct iwn_http_request *req) {
  // TODO:
  return true;
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
  ctx->base.root_route = &ctx->root->base;

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

  memcpy(&spec, spec_, sizeof(spec));
  if (spec.request_file_max_size == 0) {
    spec.request_file_max_size = 50 * 1024 * 1024;
  }
  ctx->poller = spec.http.poller;
  ctx->request_file_max_size = spec.request_file_max_size;
  spec.http.user_data = ctx;
  spec.http.on_server_dispose = _on_server_dispose;
  spec.http.request_handler = _request_handler;

  return iwn_http_server_create(&spec.http, &ctx->server_fd);
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
  }
  return 0;
}

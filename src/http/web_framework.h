#pragma once
#include "http_server.h"

IW_EXTERN_C_START

typedef enum {
  _WF_ERROR_START = (IW_ERROR_START + 205000UL),
  WF_ERROR_INVALID_FORM_DATA,                   ///< Invalid (unparseable) form data (WF_ERROR_INVALID_FORM_DATA).
  WF_ERROR_PARENT_ROUTE_FROM_DIFFERENT_CONTEXT, ///< Parent route from different context
  // (WF_ERROR_PARENT_ROUTE_FROM_DIFFERENT_CONTEXT).
  WF_ERROR_INVALID_ROUTE_PATTERN,               ///< Invalid route pattern (WF_ERROR_INVALID_ROUTE_PATTERN).
  _WF_ERROR_END,
} iwn_wf_ecode_e;

#define  IWN_WF_RES_NOT_PROCESSED    0
#define  IWN_WF_RES_PROCESSED        1
#define  IWN_WF_RES_CONNECTION_CLOSE -1
#define  IWN_WF_RES_INTERNAL_ERROR   500
#define  IWN_WF_RES_NOT_IMPLEMENTED  501
#define  IWN_WF_RES_FORBIDDEN        403
#define  IWN_WF_RES_BAD_REQUEST      400

#define IWN_WF_GET    0x01U
#define IWN_WF_PUT    0x02U
#define IWN_WF_POST   0x04U
#define IWN_WF_DELETE 0x08U
#define IWN_WF_HEAD   0x10U

struct iwn_wf_ctx;
struct iwn_wf_req;

typedef int (*iwn_wf_handler)(struct iwn_wf_req*);
typedef void (*iwn_wf_handler_dispose)(struct iwn_wf_ctx *ctx, void *handler_data);

struct iwn_wf_req {
  struct iwn_wf_ctx       *ctx;
  struct iwn_http_request *http;
  void       *handler_user_data;
  void       *request_user_data;
  void       *ctx_user_data;
  const char *target; ///< Raw request path with query data.
  const char *path;   ///< Request path stripped wfom query data.
  uint8_t     method; ///< Request method.
};

struct iwn_wf_route {
  struct iwn_wf_ctx   *ctx;
  struct iwn_wf_route *parent;
  const char    *pattern;
  uint32_t       flags;
  iwn_wf_handler handler;
  iwn_wf_handler_dispose handler_dispose;
  void       *handler_data;
  const char *tag;
};

struct iwn_wf_server_spec {
  struct iwn_http_server_spec http;
  int request_file_max_size; ///< -1: To disable file uploading. Default:  50Mb (52428800)
};

struct iwn_wf_ctx {
  const struct iwn_wf_route *root_route;
};

IW_EXPORT WUR iwrc iwn_wf_create(const struct iwn_wf_route *root_route, struct iwn_wf_ctx **out_ctx);

IW_EXPORT WUR iwrc iwn_wf_route_create(const struct iwn_wf_route *spec, struct iwn_wf_route **out_route);

IW_EXPORT WUR iwrc iwn_wf_server_create(const struct iwn_wf_server_spec *spec, struct iwn_wf_ctx *ctx);

IW_EXPORT struct iwn_poller* iwn_wf_poller_get(struct iwn_wf_ctx *ctx);

IW_EXPORT const char* iwn_wf_request_header_get(struct iwn_wf_req*, const char *name);

IW_EXPORT const char* iwn_wf_request_param_get(struct iwn_wf_req*, const char *name, const char *defval);

IW_EXPORT const char* iwn_wf_request_post_param_get(struct iwn_wf_req*, const char *name, const char *defval);

IW_EXPORT const char* iwn_wf_request_file_get(struct iwn_wf_req*, const char *name);

IW_EXPORT const char* iwn_wf_request_session_get(struct iwn_wf_req*, const char *name);

IW_EXPORT iwrc iwn_wf_session_put(struct iwn_wf_req*, const char *name, const char *data);

IW_EXPORT void iwn_wf_session_remove(struct iwn_wf_req*, const char *name);

IW_EXPORT void iwn_wf_destroy(struct iwn_wf_ctx *ctx);

IW_EXTERN_C_END

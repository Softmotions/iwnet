#pragma once
#include "http_server.h"

IW_EXTERN_C_START

#define  IWN_fr_RES_NOT_PROCESSED   0
#define  IWN_fr_RES_PROCESSED       1
#define  IWN_fr_RES_ABORT           -1
#define  IWN_fr_RES_INTERNAL_ERROR  500
#define  IWN_fr_RES_NOT_IMPLEMENTED 501
#define  IWN_fr_RES_FORBIDDEN       403
#define  IWN_fr_RES_BAD_REQUEST     400

#define IWN_fr_GET    0x01U
#define IWN_fr_PUT    0x02U
#define IWN_fr_POST   0x04U
#define IWN_fr_DELETE 0x08U
#define IWN_fr_HEAD   0x10U

struct iwn_fr_req {
  struct iwn_http_request *http;
  void       *handler_user_data;
  void       *request_user_data;
  void       *app_user_data;
  const char *target; ///< Raw request path with query data.
  const char *path;   ///< Request path stripped from query data.
  uint8_t     method; ///< Request method.
};

struct iwn_fr_ctx {
  struct iwn_http_server_spec http;
  void *app_user_data;
};

typedef void*iwn_fr_route_t;
typedef int (*iwn_fr_handler)(struct iwn_fr_req*);

IW_EXPORT WUR iwrc iwn_fr_context_create(const struct iwn_http_server_spec *spec, struct iwn_fr_ctx **out_ctx);

IW_EXPORT WUR iwrc iwn_fr_context_route(
  struct iwn_fr_ctx *ctx,
  iwn_fr_route_t    *parent,
  const char        *pattern,
  uint32_t           methods,
  iwn_fr_handler     handler,
  void              *handler_data,
  iwn_fr_route_t    *out_route,
  const char        *tag);

IW_EXPORT WUR iwrc iwn_fr_start(struct iwn_fr_ctx *ctx);

IW_EXPORT const char* iwn_fr_request_header_get(struct iwn_fr_req*, const char *name);

IW_EXPORT const char* iwn_fr_request_param_get(struct iwn_fr_req*, const char *name, const char *defval);

IW_EXPORT const char* iwn_fr_request_post_param_get(struct iwn_fr_req*, const char *name, const char *defval);

IW_EXPORT const char* iwn_fr_request_file_get(struct iwn_fr_req*, const char *name);

IW_EXPORT const char* iwn_fr_request_session_get(struct iwn_fr_req*, const char *name);

IW_EXPORT iwrc iwn_fr_session_put(struct iwn_fr_req*, const char *name, const char *data);

IW_EXPORT void iwn_fr_session_remove(struct iwn_fr_req*, const char *name);

IW_EXPORT void iwn_fr_destroy(struct iwn_fr_ctx *ctx);

IW_EXTERN_C_END

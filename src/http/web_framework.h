#pragma once
#include "http_server.h"

IW_EXTERN_C_START

#define  IWN_WFM_RES_NOT_PROCESSED   0
#define  IWN_WFM_RES_PROCESSED       1
#define  IWN_WFM_RES_ABORT           -1
#define  IWN_WFM_RES_INTERNAL_ERROR  500
#define  IWN_WFM_RES_NOT_IMPLEMENTED 501
#define  IWN_WFM_RES_FORBIDDEN       403
#define  IWN_WFM_RES_BAD_REQUEST     400

#define IWN_WFM_GET    0x01U
#define IWN_WFM_PUT    0x02U
#define IWN_WFM_POST   0x04U
#define IWN_WFM_DELETE 0x08U
#define IWN_WFM_HEAD   0x10U

struct iwn_wfm_request {
  struct iwn_http_request *http;
  void       *handler_user_data;
  void       *request_user_data;
  void       *app_user_data;
  const char *target; ///< Raw request path with query data.
  const char *path;   ///< Request path stripped from query.
  uint8_t     method; ///< Request method.
};

struct iwn_wfm_context {
  struct iwn_http_server_spec http;
  void *app_user_data;
};

typedef int (*iwn_wfm_handler)(struct iwn_wfm_request*);

IW_EXPORT WUR iwrc iwn_wfm_context_create(const struct iwn_http_server_spec *spec, struct iwn_wfm_context **out_ctx);

IW_EXPORT WUR iwrc iwn_wfm_context_route(
  struct iwn_wfm_context *ctx,
  const char             *pattern,
  uint32_t                methods,
  iwn_wfm_handler         handler,
  void                   *handler_data,
  const char             *tag);

IW_EXPORT WUR iwrc iwn_wfm_start(struct iwn_wfm_context *ctx);

IW_EXPORT void iwn_wfm_destroy(struct iwn_wfm_context *ctx);

IW_EXTERN_C_END

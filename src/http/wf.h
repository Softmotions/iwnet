#pragma once
#include "http_server.h"

IW_EXTERN_C_START

typedef enum {
  _WF_ERROR_START = (IW_ERROR_START + 205000UL),
  WF_ERROR_INVALID_FORM_DATA,                   /**< Invalid (unparseable) form data (WF_ERROR_INVALID_FORM_DATA).*/
  WF_ERROR_PARENT_ROUTE_FROM_DIFFERENT_CONTEXT,
  /**< Parent route from different context
     (WF_ERROR_PARENT_ROUTE_FROM_DIFFERENT_CONTEXT). */
  WF_ERROR_REGEXP_INVALID,                      /**< Invalid regular expression (WF_ERROR_REGEXP_INVALID) */
  WF_ERROR_REGEXP_CHARSET,
  /**< Invalid regular expression: expected ']' at end of character set
     (WF_ERROR_REGEXP_CHARSET) */
  WF_ERROR_REGEXP_SUBEXP,
  /**< Invalid regular expression: expected ')' at end of subexpression
     (WF_ERROR_REGEXP_SUBEXP) */
  WF_ERROR_REGEXP_SUBMATCH,
  /**< Invalid regular expression: expected '}' at end of submatch
     (WF_ERROR_REGEXP_SUBMATCH) */
  WF_ERROR_REGEXP_ENGINE,
  /**< Illegal instruction in compiled regular expression (please report this
     bug) (WF_ERROR_REGEXP_ENGINE) */
  WF_ERROR_UNSUPPORTED_HTTP_METHOD, /**< Unsupported HTTP method (WF_ERROR_UNSUPPORTED_HTTP_METHOD) */
  WF_ERROR_MAX_NESTED_ROUTES,       /**<  Exceeds max number of nested routes: 127 (WF_ERROR_MAX_NESTED_ROUTES) */
  _WF_ERROR_END,
} iwn_wf_ecode_e;

#define  IWN_WF_RES_NOT_PROCESSED    0
#define  IWN_WF_RES_PROCESSED        1
#define  IWN_WF_RES_CONNECTION_CLOSE -1
#define  IWN_WF_RES_INTERNAL_ERROR   500
#define  IWN_WF_RES_NOT_IMPLEMENTED  501
#define  IWN_WF_RES_FORBIDDEN        403
#define  IWN_WF_RES_BAD_REQUEST      400

// Route methods:
#define IWN_WF_GET            0x01U
#define IWN_WF_PUT            0x02U
#define IWN_WF_POST           0x04U
#define IWN_WF_DELETE         0x08U
#define IWN_WF_HEAD           0x10U
#define IWN_WF_OPTIONS        0x20U
#define IWN_WF_PATCH          0x40U
#define IWN_WF_FLAG_MATCH_END 0x80U

struct iwn_wf_ctx;
struct iwn_wf_req;

typedef int (*iwn_wf_handler)(struct iwn_wf_req*);
typedef void (*iwn_wf_handler_dispose)(struct iwn_wf_ctx *ctx, void *user_data);
typedef void (*iwn_wf_request_dispose)(struct iwn_wf_req*);

struct iwn_wf_req {
  struct iwn_wf_ctx       *ctx;
  struct iwn_http_request *http;
  iwn_wf_request_dispose   request_dispose;
  void       *handler_user_data;
  void       *request_user_data;
  const char *path;           ///< Full request path except query string
  const char *path_unmatched; ///< Rest of path not consumed by previous router matcher.
  uint8_t     method;         ///< Request method.
};

struct iwn_wf_route {
  struct iwn_wf_ctx   *ctx;
  struct iwn_wf_route *parent;
  const char    *pattern;
  uint32_t       flags;
  iwn_wf_handler handler;
  iwn_wf_handler_dispose handler_dispose;
  void       *user_data;
  const char *tag;
};

struct iwn_wf_server_spec {
  struct iwn_poller *poller;                       ///< Required poller reference.
  const char *listen;
  const char *certs;
  ssize_t     certs_len;
  const char *private_key;
  ssize_t     private_key_len;
  int port;                           ///< Default: 8080 http, 8443 https
  int socket_queue_size;              ///< Default: 64
  int request_buf_max_size;           ///< Default: 8Mb
  int request_buf_size;               ///< Default: 1024
  int request_file_max_size;          ///< -1: To disable chunked requests and files uploading. Default:  50Mb
  // (52428800)
  int  request_max_headers_count;     ///< Default:  127
  int  request_timeout_keepalive_sec; ///< -1 Disable timeout, 0 Use default timeout: 120sec
  int  request_timeout_sec;           ///< -1 Disable timeout, 0 Use default timeout: 20sec
  int  request_token_max_len;         ///< Default: 8192
  int  response_buf_size;             ///< Default: 1024
  bool certs_in_buffer;               ///< true if `certs_data` specified as data buffer rather a file name.
  bool private_key_in_buffer;         ///< true if `private_key_in_buffer` specified as data buffer rather a file name.
};

struct iwn_wf_ctx {
  const struct iwn_wf_route *root;
};

IW_EXPORT WUR iwrc iwn_wf_create(const struct iwn_wf_route *root_route_spec, struct iwn_wf_ctx **out_ctx);

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

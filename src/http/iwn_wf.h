#pragma once

#include "iwn_http_server.h"

#include <stdio.h>

IW_EXTERN_C_START

typedef enum {
  _WF_ERROR_START = (IW_ERROR_START + 205000UL),
  WF_ERROR_INVALID_FORM_DATA,                   /**< Invalid (unparseable) form data (WF_ERROR_INVALID_FORM_DATA).*/
  WF_ERROR_PARENT_ROUTE_FROM_DIFFERENT_CONTEXT,
  /**< Parent route from different context
     (WF_ERROR_PARENT_ROUTE_FROM_DIFFERENT_CONTEXT). */
  WF_ERROR_REGEXP_INVALID,                      /**< Invalid regular expression (WF_ERROR_REGEXP_INVALID) */
  /**< Illegal instruction in compiled regular expression (please report this
     bug) (WF_ERROR_REGEXP_ENGINE) */
  WF_ERROR_UNSUPPORTED_HTTP_METHOD, /**< Unsupported HTTP method (WF_ERROR_UNSUPPORTED_HTTP_METHOD) */
  WF_ERROR_MAX_NESTED_ROUTES,       /**<  Exceeds the max number of nested routes: 127 (WF_ERROR_MAX_NESTED_ROUTES) */
  WF_ERROR_CURL_API,                /**< CUrl API call error. () */
  _WF_ERROR_END,
} iwn_wf_ecode_e;

#define IWN_WF_SESSION_ID_LEN     32
#define IWN_WF_SESSION_COOKIE_KEY "sessionid"

#define  IWN_WF_RES_NOT_PROCESSED     0
#define  IWN_WF_RES_PROCESSED         1
#define  IWN_WF_RES_CONNECTION_CLOSE  -1
#define  IWN_WF_RES_SKIP_CHILD_ROUTES -2
#define  IWN_WF_RES_FORBIDDEN         403
#define  IWN_WF_RES_BAD_REQUEST       400
#define  IWN_WF_RES_INTERNAL_ERROR    500
#define  IWN_WF_RES_NOT_IMPLEMENTED   501

// Methods
#define IWN_WF_GET         0x01U
#define IWN_WF_PUT         0x02U
#define IWN_WF_POST        0x04U
#define IWN_WF_DELETE      0x08U
#define IWN_WF_HEAD        0x10U
#define IWN_WF_OPTIONS     0x20U
#define IWN_WF_PATCH       0x40U
#define IWN_WF_METHODS_ALL (IWN_WF_GET | IWN_WF_PUT | IWN_WF_POST | IWN_WF_DELETE | IWN_WF_HEAD | IWN_WF_OPTIONS \
                            | IWN_WF_PATCH)
/// Route specific flags
#define IWN_WF_MATCH_PREFIX 0x100U

/// Request specific flags
#define IWN_WF_FORM_MULTIPART   0x200U
#define IWN_WF_FORM_URL_ENCODED 0x400U
#define IWN_WF_FORM_ALL         (IWN_WF_FORM_MULTIPART | IWN_WF_FORM_URL_ENCODED)

struct iwn_wf_ctx;
struct iwn_wf_req;

typedef int (*iwn_wf_handler)(struct iwn_wf_req*, void *user_data);
typedef void (*iwn_wf_handler_dispose)(struct iwn_wf_ctx*, void *user_data);

struct iwn_wf_route_submatch {         ///< Route regexp submatch node
  const char *input;                   ///< Matched input
  const char *sp;                      ///< Pointer to start of submatch
  const char *ep;                      ///< Pointer to the end of submatch (exclusive)
  const struct iwn_wf_route    *route; ///< Matched route
  struct iwn_wf_route_submatch *next;
};

/// HTTP request object.
struct iwn_wf_req {
  struct iwn_wf_ctx   *ctx;
  struct iwn_http_req *http;
  const char *path;           ///< Full request path except query string
  const char *path_unmatched; ///< Rest of path not consumed by previous router matcher.
  const char *path_matched;   ///< Start position of last match section of the path
  const char *body;
  size_t      body_len;
  struct iwn_wf_route_submatch *first;
  struct iwn_wf_route_submatch *last;
  struct iwn_pairs query_params;
  struct iwn_pairs form_params;
  uint32_t flags;             ///< Request method, form flags.
};

/// Route specification.
struct iwn_wf_route {
  struct iwn_wf_ctx *ctx;
  const struct iwn_wf_route *parent;
  const char    *pattern;
  uint32_t       flags;
  iwn_wf_handler handler;
  iwn_wf_handler_dispose handler_dispose;
  void       *user_data;
  const char *tag;
};

struct iwn_wf_session_store {
  /// Gets session value under the specified key.
  /// Returned value should be freed by `free()`
  char* (*get)(struct iwn_wf_session_store *store, const char *sid, const char *key);
  iwrc  (*put)(struct iwn_wf_session_store *store, const char *sid, const char *key, const char *val);
  void  (*del)(struct iwn_wf_session_store *store, const char *sid, const char *key);
  void  (*clear)(struct iwn_wf_session_store *store, const char *sid);
  void  (*dispose)(struct iwn_wf_session_store *store);
  void *user_data;
};

struct iwn_wf_server_spec {
  struct iwn_poller *poller;                       ///< Required poller reference.
  struct iwn_http_server_ssl_spec ssl;
  struct iwn_wf_session_store     session_store;
  const char *listen;
  int port;                           ///< Default: 8080 http, 8443 https
  int socket_queue_size;              ///< Default: 64
  int request_buf_max_size;           ///< Default: 8Mb
  int request_buf_size;               ///< Default: 1024
  int request_file_max_size;          ///< -1: To disable chunked requests and files uploading. Default:  50Mb
  int request_max_headers_count;      ///< Default:  127
  int request_timeout_keepalive_sec;  ///< -1 Disable timeout, 0 Use default timeout: 120sec
  int request_timeout_sec;            ///< -1 Disable timeout, 0 Use default timeout: 20sec
  int request_token_max_len;          ///< Default: 8192
};

struct iwn_wf_ctx {
  const struct iwn_wf_route *root;
};

IW_EXPORT WUR iwrc iwn_wf_create(const struct iwn_wf_route *root, struct iwn_wf_ctx **out_ctx);

IW_EXPORT WUR iwrc iwn_wf_route(const struct iwn_wf_route *spec, struct iwn_wf_route **out_route);

IW_EXPORT WUR iwrc iwn_wf_server(const struct iwn_wf_server_spec *spec, struct iwn_wf_ctx *ctx);

IW_EXPORT struct iwn_poller* iwn_wf_poller_get(struct iwn_wf_ctx *ctx);

IW_EXPORT int iwn_wf_server_fd_get(struct iwn_wf_ctx *ctx);

IW_EXPORT const char* iwn_wf_header_val_part_next(
  const char      *header_val,
  const char      *ptr,
  const char      *header_val_end,
  struct iwn_pair *out);

IW_EXPORT struct iwn_pair iwn_wf_header_val_part_find(
  const char *header_val,
  const char *header_val_end,
  const char *part_name);

IW_EXPORT struct iwn_pair iwn_wf_header_part_find(
  struct iwn_wf_req*,
  const char *header_name,
  const char *part_name);

IW_EXPORT const char* iwn_wf_session_id(struct iwn_wf_req *req);

IW_EXPORT IW_ALLOC char* iwn_wf_session_get(struct iwn_wf_req*, const char *key);

IW_EXPORT iwrc iwn_wf_session_put(struct iwn_wf_req*, const char *key, const char *data);

IW_EXPORT iwrc iwn_wf_session_printf(struct iwn_wf_req*, const char *key, const char *fmt, ...)
__attribute__((format(__printf__, 3, 4)));

IW_EXPORT iwrc iwn_wf_session_printf_va(struct iwn_wf_req*, const char *key, const char *fmt, va_list va);

IW_EXPORT void iwn_wf_session_del(struct iwn_wf_req*, const char *key);

IW_EXPORT void iwn_wf_session_clear(struct iwn_wf_req*);

struct iwn_wf_cookie_opts {
  const char *path;
  const char *domain;
  const char *extra;
  int  max_age_sec;
  bool httponly;
  bool secure;
};

/// `",;/` in `value` must be escaped.
IW_EXPORT iwrc iwn_wf_cookie_add(
  struct iwn_wf_req*,
  const char                     *name,
  const char                     *value,
  const struct iwn_wf_cookie_opts opts);

IW_EXPORT void iwn_wf_destroy(struct iwn_wf_ctx *ctx);

IW_EXTERN_C_END

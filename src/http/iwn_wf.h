#pragma once

/// High level HTTP web-framework.

#include "iwn_http_server.h"
#include <iowow/iwlog.h>
#include <stdio.h>

IW_EXTERN_C_START

/// Error codes specific to web-framework module.
typedef enum {
  _WF_ERROR_START = (IW_ERROR_START + 205000UL),
  WF_ERROR_INVALID_FORM_DATA,                   ///< Invalid (unparseable) form data (WF_ERROR_INVALID_FORM_DATA)
  WF_ERROR_PARENT_ROUTE_FROM_DIFFERENT_CONTEXT,
  /**< Parent route from different context
     (WF_ERROR_PARENT_ROUTE_FROM_DIFFERENT_CONTEXT). */
  WF_ERROR_REGEXP_INVALID,                      ///< Invalid regular expression (WF_ERROR_REGEXP_INVALID)
  /**< Illegal instruction in compiled regular expression (please report this
     bug) (WF_ERROR_REGEXP_ENGINE) */
  WF_ERROR_UNSUPPORTED_HTTP_METHOD, ///< Unsupported HTTP method (WF_ERROR_UNSUPPORTED_HTTP_METHOD)
  WF_ERROR_MAX_NESTED_ROUTES,       ///<  Exceeds the max number of nested routes: 127 (WF_ERROR_MAX_NESTED_ROUTES)
  WF_ERROR_CURL_API,                ///< CUrl API call error.
  _WF_ERROR_END,
} iwn_wf_ecode_e;

#define IWN_WF_SESSION_ID_LEN     32
#define IWN_WF_SESSION_COOKIE_KEY "sessionid"

/// @defgroup wf_handler_return_value Constants as route handlers return values
/// @see iwn_wf_handler
/// @{
#define  IWN_WF_RES_NOT_PROCESSED 0      ///< Request is not handled by route handler.
                                         /// Farther processing of route request handlers (iwn_wf_handler) allowed.
#define  IWN_WF_RES_PROCESSED         1  ///< Request is processed by route handler, response was sent.
#define  IWN_WF_RES_CONNECTION_CLOSE  -1 ///< Abort request processing, close network connection.
#define  IWN_WF_RES_SKIP_CHILD_ROUTES -2 ///< Skip processing of child routes.

/// Frequently used status codes as return value from route handler.
#define  IWN_WF_RES_FORBIDDEN       403
#define  IWN_WF_RES_BAD_REQUEST     400
#define  IWN_WF_RES_INTERNAL_ERROR  500
#define  IWN_WF_RES_NOT_IMPLEMENTED 501
/// @}

/// @defgroup wf_flags HTTP Methods and request status flags.
/// @see iwn_wf_req::flags
/// @see iwn_wf_route::flags
/// @{
#define IWN_WF_GET         0x01U
#define IWN_WF_PUT         0x02U
#define IWN_WF_POST        0x04U
#define IWN_WF_DELETE      0x08U
#define IWN_WF_HEAD        0x10U
#define IWN_WF_OPTIONS     0x20U
#define IWN_WF_PATCH       0x40U
#define IWN_WF_METHODS_ALL (IWN_WF_GET | IWN_WF_PUT | IWN_WF_POST | IWN_WF_DELETE | IWN_WF_HEAD | IWN_WF_OPTIONS \
                            | IWN_WF_PATCH)

/// With this flag a route pattern is matched even if it matches only prefix part of request path.
/// This flag is set automatically for routes having child subroutes.
#define IWN_WF_MATCH_PREFIX 0x100U

/// Request specific flags.
/// @see iwn_wf_req::flags
#define IWN_WF_FORM_MULTIPART   0x200U
#define IWN_WF_FORM_URL_ENCODED 0x400U
#define IWN_WF_FORM_ALL         (IWN_WF_FORM_MULTIPART | IWN_WF_FORM_URL_ENCODED)
/// @}

struct iwn_wf_ctx;
struct iwn_wf_req;

/// Route request handler.
///
/// A handler function is called when request matched to its route configuration:
/// - iwn_wf_route::pattern
/// - iwn_wf_route::flags
///
/// Handler user data `user_data` is supplied from route configuration iwn_wf_route::user_data.
///
/// - If returned value is greater than `1` it will be interpreted as HTTP status code and
///   appropriate client response will be generated.
/// - ` 0` (IWN_WF_RES_NOT_PROCESSED) Handler doesn't write a response. Next matched routes will be processed.
/// - ` 1` (IWN_WF_RES_PROCESSED) Request was fully processed by handler and HTTP response has been sent to client.
/// - `-1` (IWN_WF_RES_CONNECTION_CLOSE) Request connection should be closed, response should be aborted.
/// - `-2` (IWN_WF_RES_SKIP_CHILD_ROUTES) Skip processing of child routes.
///
/// @warning Double check what handler function will always return `1` (IWN_WF_RES_PROCESSED)
///          When `iwn_http_response_write()` or `iwn_http_response_printf()` was called by handler.
///          Otherwise app will meet undefined memory access behavior.
///
/// @see wf_handler_return_value
typedef int (*iwn_wf_handler)(struct iwn_wf_req*, void *user_data);

/// Route disposition callback.
typedef void (*iwn_wf_handler_dispose)(struct iwn_wf_ctx*, void *user_data);

/// Request path regexp submatch entry.
struct iwn_wf_route_submatch {         ///< Route regexp submatch node.
  const char *input;                   ///< Matched input.
  const char *sp;                      ///< Pointer to start of submatch.
  const char *ep;                      ///< Pointer to the end of submatch (exclusive).
  const struct iwn_wf_route    *route; ///< Matched route.
  struct iwn_wf_route_submatch *next;  ///< Next submatch in chain.
};

/// Web-framework HTTP request object.
struct iwn_wf_req {
  struct iwn_wf_ctx   *ctx;            ///< Framework context.
  struct iwn_http_req *http;           ///< Low level HTTP request object.
  const char *path;                    ///< Full request path except query string.
  const char *path_unmatched;          ///< Rest of path not consumed by previous router matcher.
  const char *path_matched;            ///< Start position of last match section of the path.
  const char *body;                    ///< Pointer to the `\0` terminated request body.
  size_t      body_len;                ///< Length of request body.
  struct iwn_wf_route_submatch *first; ///< First regexp request path submatch.
  struct iwn_wf_route_submatch *last;  ///< Last regexp request path submatch.
  struct iwn_wf_route *route;          ///< Current route processed by route handler.

  /// Request URL query parameters list.
  /// @note key/value buffers are zero terminated strings.
  struct iwn_pairs query_params;

  /// Request form data parameters list.
  /// @note key/value buffers are zero terminated strings.
  struct iwn_pairs form_params;

  /// Request method, form flags.
  /// see IWN_WF_<METHOD>, IWN_WF_FORM_MULTIPART,IWN_WF_FORM_URL_ENCODED
  uint32_t flags;
};

/// Web-framework Route configuration.
struct iwn_wf_route {
  struct iwn_wf_ctx *ctx;                 ///< Web-framework context associated with route.
  const struct iwn_wf_route *parent;      ///< Optional parent route.
  /// A route matching pattern.
  /// To be consistent in pattern matching follow the these rules:
  /// - Non regexp patterns start with: `/` Eg: `/hello/name`
  /// - Regular expression patterns start with: `^/` Eg: `^/hello.*`
  const char    *pattern;
  uint32_t       flags;                   ///< Matching flags @ref wf_flags
  iwn_wf_handler handler;                 ///< Optional route handler.
  iwn_wf_handler_dispose handler_dispose; ///< Optional handler dispose callback.
  void       *user_data;                  ///< Optional route handler user data.
  const char *tag;                        ///< Constant string tag associated with routed, used for debugging.
};

/// Configuration of HTTP session storage backend.
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

/// HTTP server configuration.
struct iwn_wf_server_spec {
  struct iwn_poller *poller;                     ///< A poller. Required.
  struct iwn_http_server_ssl_spec ssl;           ///< TLS server parameters.
  struct iwn_wf_session_store     session_store; ///< HTTP session store configuration.
  iwn_http_server_proxy_handler   proxy_handler; ///< HTTP proxy session setup handler.
  const char *listen;                            ///< Server listen hostname. Default: localhost
  int port;                                      ///< Default: 8080 http, 8443 https
  int socket_queue_size;                         ///< Default: 64
  int request_buf_max_size;                      ///< Default: 8Mb
  int request_buf_size;                          ///< Default: 1024
  int request_file_max_size;                     ///< -1: To disable chunked requests and files uploading.
                                                 /// Default: 50Mb
  int request_max_headers_count;                 ///< Default: 127
  int request_timeout_keepalive_sec;             ///< -1 Disable timeout, 0 Use default timeout: 120sec
  int request_timeout_sec;                       ///< -1 Disable timeout, 0 Use default timeout: 20sec
  int request_token_max_len;                     ///< Default: 8192
};

/// Web-framework configuration context.
struct iwn_wf_ctx {
  /// Context root route configuration.
  const struct iwn_wf_route *root;
};

/// Create a web-framework context.
/// Web-framework context must be created with root route configuration.
/// @note Root route handler is called for requests not handled by other route handlers.
/// @param root Optional. Root route configuration. Pattern doesn't makes sense for root router.
/// @param[out] Output context. Should be disposed by `iwn_wf_destroy()`
///
IW_EXPORT WUR iwrc iwn_wf_create(const struct iwn_wf_route *root, struct iwn_wf_ctx **out_ctx);

/// Register new route.
/// @param spec Route configuration.
/// @param[out] Optional placeholder to store resulted route configuration.
///             Used when you build hierarchy of routes.
IW_EXPORT WUR iwrc iwn_wf_route(const struct iwn_wf_route *spec, struct iwn_wf_route **out_route);

/// Create HTTP server associated with web-framework context.
/// If poller is active @ref iwn_poller_poll() server will process incoming HTTP request according
/// to the routes configuration.
IW_EXPORT WUR iwrc iwn_wf_server(const struct iwn_wf_server_spec *spec, struct iwn_wf_ctx *ctx);

/// Print routes configuration to the given `out` file.
/// @note Use @ref iwn_wf_route::tag routes labeling.
IW_EXPORT void iwn_wf_route_print(const struct iwn_wf_route*, FILE *out);

/// Returns a poller associated with framework context.
IW_EXPORT struct iwn_poller* iwn_wf_poller_get(struct iwn_wf_ctx *ctx);

/// Returns server socket fd.
IW_EXPORT int iwn_wf_server_fd_get(struct iwn_wf_ctx *ctx);

/// Find the first regular expression submatch part for the current route.
IW_EXPORT struct iwn_wf_route_submatch* iwn_wf_request_submatch_first(const struct iwn_wf_req*);

/// Find the last regular expression submatch part for the current route.
IW_EXPORT struct iwn_wf_route_submatch* iwn_wf_request_submatch_last(const struct iwn_wf_req*);

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

/// Returns a session id associated with request or zero if no session created.
IW_EXPORT const char* iwn_wf_session_id(struct iwn_wf_req*);

/// Associate a request with session id.
/// @note Session id must be zero terminated character string with length `IWN_WF_SESSION_ID_LEN`
IW_EXPORT iwrc iwn_wf_session_id_set(struct iwn_wf_req*, const char *sid);

/// Returns a string data stored in session by given `key`.
IW_EXPORT const char* iwn_wf_session_get(struct iwn_wf_req*, const char *key);

/// Store some zero terminated data buffer in request session under specified `key`.
IW_EXPORT iwrc iwn_wf_session_put(struct iwn_wf_req*, const char *key, const char *data);

/// Store printf formatted data in request session under specified `key`.
IW_EXPORT iwrc iwn_wf_session_printf(struct iwn_wf_req*, const char *key, const char *fmt, ...)
__attribute__((format(__printf__, 3, 4)));

IW_EXPORT iwrc iwn_wf_session_printf_va(struct iwn_wf_req*, const char *key, const char *fmt, va_list va);

/// Remove session data under given `key`.
IW_EXPORT void iwn_wf_session_del(struct iwn_wf_req*, const char *key);

/// Remove all data from session associated with request.
IW_EXPORT void iwn_wf_session_clear(struct iwn_wf_req*);

struct iwn_wf_cookie_opts {
  const char *path;
  const char *domain;
  const char *extra;
  int  max_age_sec;
  bool httponly;
  bool secure;
};

/// Set a cookie in HTTP response.
/// `",;/` in `value` must be escaped.
IW_EXPORT iwrc iwn_wf_cookie_add(
  struct iwn_wf_req*,
  const char                     *name,
  const char                     *value,
  const struct iwn_wf_cookie_opts opts);

/// Destroy web-framework configuration and stops an HTTP server.
IW_EXPORT void iwn_wf_destroy(struct iwn_wf_ctx *ctx);

IW_EXTERN_C_END

#pragma once

#include "iwn_wf.h"
#include <iowow/iwjson.h>
#include <stdarg.h>

IW_EXTERN_C_START

struct iwn_ws_handler_spec;

struct iwn_ws_sess {
  struct iwn_wf_req *req;
  struct iwn_ws_handler_spec *spec;
};

/// Websocket messages handler.
///
/// @param sess ebsocket session.
/// @param msg Zero terminated websocket message.
/// @param msg_len Message length.
/// @return `false` if websocket connection should be terminated.
///
typedef bool (*iwn_ws_msg_handler)(struct iwn_ws_sess *sess, const char *msg, size_t msg_len, uint8_t frame);

/// Websocket HTTP server route configuration.
struct iwn_ws_handler_spec {
  iwn_ws_msg_handler handler; ///< Websocket messages handler. Required.
  void *user_data;            ///< Message handler user data.
  int   (*on_http_init)(struct iwn_wf_req*, struct iwn_ws_handler_spec *spec);
  bool  (*on_session_init)(struct iwn_ws_sess*);
  void  (*on_session_dispose)(struct iwn_ws_sess*);
  iwn_wf_handler_dispose on_handler_dispose;
  uint8_t flags;
};

/// Writes `buf` data into websocket data channel.
/// @return `false` if write operation has been failed.
///
IW_EXPORT bool iwn_ws_server_write(struct iwn_ws_sess*, const char *buf, ssize_t buf_len);

IW_EXPORT bool iwn_ws_server_write_fd(struct iwn_poller *p, int fd, const char *buf, ssize_t buf_len);

IW_EXPORT bool iwn_ws_server_write_json(struct iwn_ws_sess*, struct jbl_node *json);

IW_EXPORT bool iwn_ws_server_write_json_fd(struct iwn_poller *p, int fd, struct jbl_node *json);

/// Writes prinf formatted messages into websocket data channel.
/// @return `false` if write operation failed.
///
IW_EXPORT bool iwn_ws_server_printf(struct iwn_ws_sess*, const char *fmt, ...)
__attribute__((format(__printf__, 2, 3)));

IW_EXPORT bool iwn_ws_server_printf_va(struct iwn_ws_sess*, const char *fmt, va_list va);

IW_EXPORT bool iwn_ws_server_write_binary(struct iwn_ws_sess*, const char *buf, ssize_t buf_len);

IW_EXPORT bool iwn_ws_server_write_binary_fd(struct iwn_poller *p, int fd, const char *buf, ssize_t buf_len);

IW_EXPORT bool iwn_ws_server_ping(struct iwn_ws_sess*, const char *buf, ssize_t buf_len);

IW_EXPORT bool iwn_ws_server_ping_fd(struct iwn_poller *p, int fd, const char *buf, ssize_t buf_len);

IW_EXPORT void iwn_ws_server_session_close(struct iwn_ws_sess *sess);

/// Creates websocket channel route based on given `route` template.
/// @param route Basic route configuration.
/// @return Websocket server route configuration or zero on error.
///
IW_EXPORT struct iwn_wf_route* iwn_ws_server_route_attach(
  struct iwn_wf_route              *route,
  const struct iwn_ws_handler_spec *spec);

IW_EXTERN_C_END

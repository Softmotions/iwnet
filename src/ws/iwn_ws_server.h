#pragma once

#include "iwn_ws.h"
#include "iwn_wf.h"

#include <stdarg.h>

IW_EXTERN_C_START

struct iwn_ws_handler_spec;

struct iwn_ws_sess {
  struct iwn_wf_req *req;
  struct iwn_ws_handler_spec *spec;
};

typedef bool (*iwn_ws_msg_handler)(struct iwn_ws_sess *sess, const char *msg, size_t msg_len);

struct iwn_ws_handler_spec {
  iwn_ws_msg_handler handler; ///< Websocket messages handler. Required.
  void *user_data;            ///< Message handler user data.
  int   (*on_http_init)(struct iwn_wf_req*, struct iwn_ws_handler_spec *spec);
  bool  (*on_session_init)(struct iwn_ws_sess*);
  void  (*on_session_dispose)(struct iwn_ws_sess*);
  iwn_wf_handler_dispose on_handler_dispose;
};

IW_EXPORT bool iwn_ws_server_write(struct iwn_ws_sess*, const char *buf, ssize_t buf_len);

IW_EXPORT bool iwn_ws_server_printf(struct iwn_ws_sess*, const char *fmt, ...)
__attribute__((format(__printf__, 2, 3)));

IW_EXPORT bool iwn_ws_server_printf_va(struct iwn_ws_sess*, const char *fmt, va_list va);

IW_EXPORT struct iwn_wf_route* iwn_ws_server_route_attach(
  struct iwn_wf_route              *route,
  const struct iwn_ws_handler_spec *spec);

IW_EXTERN_C_END

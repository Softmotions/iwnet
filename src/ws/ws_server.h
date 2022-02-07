#include "ws.h"
#include "wf.h"

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
  bool  (*on_session_init)(struct iwn_ws_sess*);
  void  (*on_session_dispose)(struct iwn_ws_sess*);
};

IW_EXPORT bool iwn_ws_server_write_text(struct iwn_ws_sess*, const char *buf, size_t buf_len);

IW_EXPORT struct iwn_wf_route* iwn_ws_server_route_attach(
  struct iwn_wf_route              *route,
  const struct iwn_ws_handler_spec *spec);

IW_EXTERN_C_END

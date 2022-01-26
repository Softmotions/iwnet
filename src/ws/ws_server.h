#include "ws.h"
#include "wf.h"

IW_EXTERN_C_START

struct iwn_ws_handler_spec;

struct iwn_ws_sess {
  // TODO:
  struct iwn_ws_handler_spec *spec;
};

typedef bool (*iwn_ws_msg_handler)(struct iwn_ws_sess *sess, const char *msg, size_t msg_len);

struct iwn_ws_handler_spec {
  iwn_ws_msg_handler msg_handler;
  void *msg_handler_user_data;
  void  (*on_session_init)(struct iwn_ws_sess*);
  void  (*on_session_dispose)(struct iwn_ws_sess*);
  void  (*handler_spec_dispose)(struct iwn_ws_handler_spec*);
};

IW_EXPORT bool iwn_ws_sess_write(struct iwn_ws_sess*, const char *msg, size_t msg_len);

IW_EXPORT int iwn_ws_server_handler(struct iwn_wf_req*, void *user_data);

IW_EXPORT void iwn_ws_server_handler_dispose(struct iwn_wf_ctx*, void*);

IW_EXTERN_C_END

#include "ws.h"

IW_EXTERN_C_START

struct iwn_ws_client;

struct iwn_ws_client_ctx {
  struct iwn_poller    *poller;
  struct iwn_ws_client *ws;
  void *user_data;
};

#define IWN_WS_VERIFY_PEER 0x01U
#define IWN_WS_VERIFY_HOST 0x02U

struct iwn_ws_client_spec {
  const char *url;                                                                          ///< Required
  struct iwn_poller *poller;                                                                ///< Required
  void (*on_message)(const char *buf, size_t buf_len, const struct iwn_ws_client_ctx *ctx); ///< Required
  void (*on_dispose)(const struct iwn_ws_client_ctx *ctx);                                  ///< Required
  void (*on_connected)(const struct iwn_ws_client_ctx *ctx);

  void   *user_data;
  long    timeout_sec; ///< Comm inactivity timeout
  uint8_t flags;       ///< `IWN_WS_VERIFY_*` flags
};

IW_EXPORT iwrc iwn_ws_client_open(const struct iwn_ws_client_spec *spec, struct iwn_ws_client **out_ws);

/// Notify poller to close websocket. `on_dispose` handler will be called afterward.
IW_EXPORT void iwn_ws_client_close(struct iwn_ws_client *ws);

IW_EXPORT bool iwn_ws_client_write_text(struct iwn_ws_client *ws, const void *buf, size_t buf_len);

IW_EXTERN_C_END

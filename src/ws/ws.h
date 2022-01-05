#pragma once

#include "poller.h"

IW_EXTERN_C_START

typedef enum {
  _WS_ERROR_START = (IW_ERROR_START + 203000UL),
  WS_ERROR_INVALID_URL,          ///< Invalid URL (WS_ERROR_INVALID_URL)
  WS_ERROR_PEER_CONNECT,         ///< Peer connection failed (WS_ERROR_PEER_CONNECT)
  WS_ERROR_HANDSHAKE,            ///< Websocket handshake error (WS_ERROR_HANDSHAKE)
  WS_ERROR_HANDSHAKE_CLIENT_KEY, ///< Websocket handshake client key validation error (WS_ERROR_HANDSHAKE_CLIENT_KEY)
  WS_ERROR_CHANNEL_CLOSED,       ///< Websocket communication channel is closed (WS_ERROR_CHANNEL_CLOSED)
  WS_ERROR,                      ///< Websocket generic error (WS_ERROR)
  _WS_ERROR_END,
} iwn_ws_ecode_e;

struct iwn_ws;

struct iwn_ws_ctx {
  struct iwn_poller *poller;
  struct iwn_ws     *ws;
  void *user_data;
};

#define IWN_WS_VERIFY_PEER 0x01U
#define IWN_WS_VERIFY_HOST 0x02U

struct iwn_ws_spec {
  const char *url;                                                                   ///< Required
  struct iwn_poller *poller;                                                         ///< Required
  void (*on_message)(const char *buf, size_t buf_len, const struct iwn_ws_ctx *ctx); ///< Required
  void (*on_dispose)(const struct iwn_ws_ctx *ctx);                                  ///< Required
  void (*on_connected)(const struct iwn_ws_ctx *ctx);

  void   *user_data;
  long    timeout_sec; ///< Comm inactivity timeout
  uint8_t flags;       ///< `IWN_WS_VERIFY_*` flags
};

IW_EXPORT iwrc iwn_ws_open(const struct iwn_ws_spec *spec, struct iwn_ws **out_ws);

/// Notify poller to close websocket. `on_dispose` handler will be called afterward.
IW_EXPORT void iwn_ws_close(struct iwn_ws *ws);

IW_EXPORT iwrc iwn_ws_write_text(struct iwn_ws *ws, const void *buf, size_t buf_len);

IW_EXTERN_C_END

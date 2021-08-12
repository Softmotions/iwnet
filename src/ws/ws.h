#pragma once

#include "poller.h"

typedef enum {
  _WS_ERROR_START = (IW_ERROR_START + 203000UL),
  WS_ERROR_INVALID_URL,          ///< Invalid URL (WS_ERROR_INVALID_URL)
  WS_ERROR_PEER_CONNECT,         ///< Peer connection failed (WS_ERROR_PEER_CONNECT)
  WS_ERROR_HANDSHAKE,            ///< Websocket handshake error (WS_ERROR_HANDSHAKE)
  WS_ERROR_HANDSHAKE_CLIENT_KEY, ///< Websocket handshake client key validation error (WS_ERROR_HANDSHAKE_CLIENT_KEY)
  WS_ERROR_CHANNEL_CLOSED,       ///< Websocket communication channel is closed (WS_ERROR_CHANNEL_CLOSED)
  WS_ERROR,                      ///< Websocket generic error (WS_ERROR)
  _WS_ERROR_END,
} ws_ecode_e;

struct ws;

struct ws_ctx {
  struct poller *poller;
  struct ws     *ws;
  void *user_data;
};

struct ws_spec {
  const char    *url;                                                            ///< Required
  struct poller *poller;                                                         ///< Required
  void (*on_message)(const char *buf, size_t buf_len, const struct ws_ctx *ctx); ///< Required
  void (*on_dispose)(const struct ws_ctx *ctx);                                  ///< Required
  void (*on_connected)(const struct ws_ctx *ctx);

  void *user_data;
  long  timeout_sec;           ///< Comm inactivity timeout
  bool  verify_peer;           ///< Do ssl verification on remote peer
  bool  verify_host;
};

iwrc ws_open(const struct ws_spec *spec, struct ws **out_ws);

/// Notify poller to close websocket. `on_dispose` handler will be called afterward.
void ws_close(struct ws *ws);

iwrc ws_write_text(struct ws *ws, const void *buf, size_t buf_len);

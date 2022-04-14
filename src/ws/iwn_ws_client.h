#pragma once

/// Websocket client.

#include "iwn_ws.h"

IW_EXTERN_C_START

struct iwn_ws_client;

/// Context passed into client callback functions.
struct iwn_ws_client_ctx {
  struct iwn_poller    *poller;
  struct iwn_ws_client *ws;
  void *user_data;
};

#define IWN_WS_VERIFY_PEER 0x01U /// Verify peer when SSL connection.
#define IWN_WS_VERIFY_HOST 0x02U /// Verify host when SSL connection.

/// Websocket client configuration.
struct iwn_ws_client_spec {
  /// Connection url. Required. Eg: wss://localhost/ws
  const char *url;
  struct iwn_poller *poller;                                                                ///< Required
  void (*on_message)(const char *buf, size_t buf_len, const struct iwn_ws_client_ctx *ctx); ///< Required
  void (*on_dispose)(const struct iwn_ws_client_ctx *ctx);                                  ///< Required
  void (*on_connected)(const struct iwn_ws_client_ctx *ctx);

  void   *user_data;   ///< Arbitrary user data which will referred by `iwn_ws_client_ctx`.
  long    timeout_sec; ///< Connection inactivity timeout
  uint8_t flags;       ///< `IWN_WS_VERIFY_*` flags
};

/// Opens wesocket client connection according to provided `spec`.
/// @param spec Client configuration.
/// @param[out]  out_ws Websocket client handle.
///
IW_EXPORT iwrc iwn_ws_client_open(const struct iwn_ws_client_spec *spec, struct iwn_ws_client **out_ws);

/// Force poller to close client websocket. `on_dispose` handler will be called afterward.
IW_EXPORT void iwn_ws_client_close(struct iwn_ws_client *ws);

/// Writes a message to the websocket stream.
IW_EXPORT bool iwn_ws_client_write_text(struct iwn_ws_client *ws, const void *buf, size_t buf_len);

IW_EXTERN_C_END

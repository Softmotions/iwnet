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

/// Websocket client configuration.
struct iwn_ws_client_spec {
  /// Connection url. Required. Eg: wss://localhost/ws
  const char *url;
  struct iwn_poller *poller; ///< Required

  void  (*on_message)(const struct iwn_ws_client_ctx *ctx, const char *buf, size_t buf_len, uint8_t frame);
  void  (*on_dispose)(const struct iwn_ws_client_ctx *ctx);
  void  (*on_connected)(const struct iwn_ws_client_ctx *ctx);
  char* (*on_handshake)(const struct iwn_ws_client_ctx *ctx);

  void   *user_data;   ///< Arbitrary user data which will referred by `iwn_ws_client_ctx`.
  long    timeout_sec; ///< Connection inactivity timeout
  uint8_t flags;       ///< `IWN_WS_VERIFY_*` flags

  uint8_t reconnect_attempts_num;      ///< Number of reconnect attempts. Default: 0
  uint8_t reconnect_attempt_pause_sec; ///< Number of seconds to wait before next reconnect attempt. Default: 5
};

/// Opens websocket client connection according to provided `spec`.
/// @param spec Client configuration.
/// @param[out]  out_ws Websocket client handle.
///
IW_EXPORT iwrc iwn_ws_client_open(const struct iwn_ws_client_spec *spec, struct iwn_ws_client **out_ws);

/// Force poller to close client websocket. `on_dispose` handler will be called afterward.
IW_EXPORT void iwn_ws_client_close(struct iwn_ws_client *ws);

IW_EXPORT void iwn_ws_client_close_by_fd(struct iwn_poller *p, int fd);

/// Send close frame to the underlying websocket channel.
/// @returns True if close frame was queued successfully.
IW_EXPORT bool iwn_ws_client_send_close(struct iwn_ws_client *ws);

IW_EXPORT void iwn_ws_client_send_close_by_fd(struct iwn_poller *p, int fd);

/// Releases all memory resources held by ws.
/// Actually should be called from `on_dispose()` callback.
IW_EXPORT bool iwn_ws_client_destroy(struct iwn_ws_client *ws);

/// Returns true if client connection is closed and it eligible to call `iwn_ws_client_destroy()`
IW_EXPORT bool iwn_ws_client_is_can_destroy(struct iwn_ws_client *ws);

IW_EXPORT int iwn_ws_client_fd_get(struct iwn_ws_client *ws);

/// Writes a message to the websocket stream.
IW_EXPORT bool iwn_ws_client_write_text(struct iwn_ws_client *ws, const void *buf, size_t buf_len);

IW_EXPORT bool iwn_ws_client_write_text_fd(struct iwn_poller *p, int fd, const void *buf, size_t buf_len);

IW_EXPORT bool iwn_ws_client_write_binary(struct iwn_ws_client *ws, const void *buf, size_t buf_len);

IW_EXPORT bool iwn_ws_client_write_binary_fd(struct iwn_poller *p, int fd, const void *buf, size_t buf_len);

IW_EXPORT bool iwn_ws_client_ping(struct iwn_ws_client *ws, const void *buf, size_t buf_len);

IW_EXPORT bool iwn_ws_client_ping_fd(struct iwn_poller *p, int fd, const void *buf, size_t buf_len);

IW_EXTERN_C_END

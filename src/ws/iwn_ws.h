#pragma once

#include "iwn_poller.h"

IW_EXTERN_C_START

#define WS_MAGIC13 "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

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

IW_EXTERN_C_END

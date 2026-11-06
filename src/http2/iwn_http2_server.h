#pragma once

/// HTTP/2 server transport for the low level HTTP server.
///
/// A connection is served by HTTP/2 when it is negotiated by TLS ALPN (`h2`)
/// or when the plain text HTTP/2 connection preface is detected.
/// HTTP/2 requests are delivered to the very same request handler as HTTP/1.1
/// requests, using `struct iwn_http_req` objects with the HTTP/2 operations
/// table installed.

#include "iwn_http_server.h"

IW_EXTERN_C_START;

#ifdef IWN_HTTP2

/// Attaches the HTTP/2 transport to the connection when TLS ALPN selected `h2`.
/// @param request HTTP/1 request object acting as connection anchor.
/// @return `true` if the connection was handed over to HTTP/2.
bool iwn_http2_conn_attach_alpn(struct iwn_http_req *request);

/// Attaches the HTTP/2 transport after the HTTP/2 connection preface
/// was detected on a plain text connection.
///
/// @param request HTTP/1 request object acting as connection anchor.
/// @param buf Already read bytes that follow the `PRI * HTTP/2.0\r\n\r\n` prefix.
/// @param len Length of `buf`.
/// @return `true` if the connection was handed over to HTTP/2.
bool iwn_http2_conn_attach_preface(struct iwn_http_req *request, const uint8_t *buf, size_t len);

#endif // IWN_HTTP2

IW_EXTERN_C_END;

# Pending

New records are on the top.

## HTTP/2 server transport

- `iwn_http_proxy_*` (reverse proxy) is not supported for requests served by the
  HTTP/2 transport. `iwn_http_proxy_url_set()` and friends return `false` for such requests.
- WebSocket upgrade over HTTP/2 (RFC 8441 extended CONNECT) is not implemented.
  `iwn_http_connection_set_upgrade()` and `iwn_http_inject_poller_events_handler()`
  are no-ops for HTTP/2 requests.
- h2c upgrade (`Upgrade: h2c`, RFC 9113 §3.2) is not supported. HTTP/2 is negotiated
  by TLS ALPN (`h2`) or by the HTTP/2 connection preface (prior knowledge).
- `iwn_http_connection_set_keep_alive(request, false)` has no effect on HTTP/2 requests:
  an HTTP/2 connection is shared by concurrent streams and cannot be closed per request.

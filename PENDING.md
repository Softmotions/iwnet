# Pending

New records are on the top.

## s2n-tls backend

- The s2n-tls adapter builds a `s2n_config` and parses the certificate chain/private key
  for every accepted connection (same as the BearSSL adapter does). Sharing a single
  config per server would avoid this cost.
- The s2n-tls adapter does not send the TLS `close_notify` alert on connection teardown
  (`s2n_shutdown()` is not called), it just releases the connection. This matches the
  BearSSL adapter behaviour.
- gRPC server TLS is exercised only by the C client test cases; `grpc_test_server1` uses a
  UNIX socket. The s2n server path is covered by the HTTP/WebSocket server test cases.

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

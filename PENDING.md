# Pending

New records are on the top.

## Autark cache keeps objects from a previous build configuration

- Switching between build configurations which only change compiler flags (for
  example `ENABLE_ASAN=1` -> plain, or `ENABLE_UBSAN=1` -> plain) leaves stale `*.o`
  files in `autark-cache/`: the object rules are not re-run for those switches, so
  the link fails with undefined `__asan_*`/`__ubsan_*` references. Recovering needs
  a clean rebuild (`./build.sh -c`) or removing `autark-cache/src/**/*.o` and touching
  the sources. The host tools (`tools/Autark`) no longer depend on the target flags,
  so they are not affected any more.

## s2n: the client trust store also loads the system CA certificates

- `iwn_s2n_client_config_new()` uses `s2n_config_new()`, so the system trust store is
  loaded and the `iwn_cacerts` (or user supplied) bundle is added on top of it. In an
  environment without a usable system store the client keeps working, but it pays for
  the system store load and trusts those certificates in addition to the bundle.
  Dropping the system store (switching to `s2n_config_new_minimal()`) would make the
  bundle the only trust source and needs a deliberate decision, as locally installed
  CA certificates would no longer be trusted by the TLS client.

## HTTP/1.0 request carrying `Transfer-Encoding`

- RFC 9112 §6.1: "A server or client that receives an HTTP/1.0 message containing
  a Transfer-Encoding header field MUST treat the message as if the framing is
  faulty, even if a Content-Length is present, and close the connection after
  processing the message." The request parser does not look at the request version
  while parsing `Transfer-Encoding`, so an HTTP/1.0 request with
  `Transfer-Encoding: chunked` is served using the chunked framing (the connection
  is not kept alive for HTTP/1.0 unless the client asked for it, so the "close after
  processing" part already holds).

## Reverse proxy: request headers are forwarded unparsed

- `_proxy_init()` hands the connection over to the proxy endpoint at the first
  complete request header line and streams the rest of the request (headers and
  body) verbatim. The `Content-Length`/`Transfer-Encoding` validation in the HTTP/1.1
  parser therefore only applies to requests served by iwnet itself; a proxied request
  is forwarded with whatever framing the client sent, so the upstream endpoint must
  reject ambiguous framing on its own.

## BearSSL adapter: TLS engine access from task threads

- `iwn_brssl_poller_adapter`'s `read`/`write` operate on the BearSSL engine
  without `pa::mtx`, while the poller event handler (`_on_ready`) holds that
  mutex while it flushes/decrypts records and invokes `on_event`. HTTP/2
  response flushes issued from a poller task
  (`iwn_http2_server.c::_conn_flush_task`) therefore touch the engine
  concurrently with the fd event. Adding the mutex to `read`/`write` alone
  would invert the existing lock order (the event handler holds `pa::mtx` and
  then waits for the connection mutex in `on_event`), so a fix needs the event
  handler to release `pa::mtx` around `on_event` or a dedicated engine lock.
  Found while adding TLS client stress tests to a downstream project; not
  reproduced as a failure yet.

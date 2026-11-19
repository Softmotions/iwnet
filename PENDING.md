# Pending

New records are on the top.

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

## s2n-tls backend

- The s2n-tls adapter creates a `s2n_config` and parses the certificate
  chain/private key for every accepted connection (same as the BearSSL adapter does).
  Sharing a single config per server would avoid this cost.

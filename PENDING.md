# Pending

New records are on the top.

## HTTP/2 connection lifetime during poller destroy

- Stress teardown of a closed HTTP/2 connection (destroying the poller right
  after the peer socket closed, with a deferred response flush still queued)
  can still crash/hang after v1.6.5: a `_conn_flush_task` was observed arming a
  freed `h2_conn` (`conn->poller` and `conn->pa` read from reused memory) while
  `iwn_poller_destroy()` was joining the worker pool. `_conn_defer()` checks
  `conn->sess`/`closed`/`abort` and schedules the flush without `conn->mtx`,
  but taking that mutex there would invert the existing order with an
  application request-dispose callback that may lock its own state
  (`conn->mtx` -> callback vs. application lock -> response API -> `conn->mtx`).
  A fix needs either a lifetime anchor independent of the response API path or
  a state guard that does not block the dispose callback. Found by a downstream
  TLS client stress test; single-run test suites do not reproduce it.

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

# [v1.6.2] - 2026-11-13

- http2: Fixed a race between deferred response writes issued from a non-handler
  thread (`iwn_http_response_stream_write()`, `iwn_http_response_chunk_write()`,
  `iwn_http_response_stream_end()`, `iwn_http_response_chunk_end()`,
  `iwn_http_request_abort()`) and the connection flush. The pending write queue
  is appended to under the leaf `out_mtx` lock, but the flush detached it under
  the connection mutex only; a concurrent writer could push into the detached
  list and leave a freed entry in `conn->out_queue`, crashing the poller task
  later in `_conn_unref()`.

# [v1.6.1] - 2026-11-13

- http2: Streamed and chunked response data writes, `iwn_http_response_stream_end()`,
  `iwn_http_response_chunk_end()` and the new `iwn_http_request_abort()` are now thread safe.
  Writes issued from a thread other than the request handler thread are queued on the
  connection and applied by the poller thread, which keeps the libhive session single
  threaded (`IWN_HTTP_THREADSAFE_RESPONSE_WRITES`). Response header/status setters and
  `iwn_http_response_stream_start()` remain handler thread APIs.
- http2: Added `iwn_http_request_abort()` which resets a request stream with
  `RST_STREAM(CANCEL)` (`IWN_HTTP_RESPONSE_ABORT`). An endless request body stream can now
  be terminated by the application; HTTP/1.1 closes the connection after the response.
- http2: Added `iwn_http_response_pending()` returning the response payload bytes which are
  not yet handed over to the transport (`IWN_HTTP_RESPONSE_PENDING`).
- http2: A DATA provider which reports `again == false` and has nothing to produce is no
  longer re-polled up to `H2_MAX_CHUNK_ITER` times per send; a pending EOF is still
  delivered by the same invocation.
- poller: `iwn_poller_destroy()` now joins the thread created by
  `iwn_poller_poll_in_thread()`. Destroying a poller right after
  `iwn_poller_shutdown_request()` could free the slot map while the dedicated poll thread
  was still in its cleanup loop (use after free).
- poller: The direct and BearSSL poller adapters use `send(..., MSG_NOSIGNAL)` on Linux/BSD.
  A peer that disconnects in the middle of a response no longer raises `SIGPIPE` in the
  host process.
- iwnet.h: `IW_BLOCKS` is defined only when clang blocks (`__BLOCKS__`) are available.

# [v1.6.0] - 2026-11-07

- ssl: Added an optional AWS s2n-tls (TLS 1.2/1.3) TLS backend (`IWN_ENABLE_S2N`, default off).
  TLS connections now go through the new `iwn_tls_poller_adapter.h` layer and the
  implementation is selected per server/client. The default `IWN_TLS_IMPL_BEARSSL` keeps the
  previous BearSSL TLS 1.2 behaviour. `s2n-tls` is fetched and built by `s2n.autark` and
  requires `cmake` plus OpenSSL `libcrypto` development files.
- Autark: Renamed the `ENABLE_GRPC` option to `IWN_ENABLE_GRPC` and `ENABLE_HTTP2` to
  `IWN_ENABLE_HTTP2`.
- Tests: HTTP, gRPC and websocket TLS cases can be run against the s2n-tls backend with the
  `IWN_TEST_TLS=s2n` environment variable; the suite runs them automatically when built with
  `IWN_ENABLE_S2N=1`.
- iwn_http_server: Added optional HTTP/2 server transport (`ENABLE_HTTP2`, based on libhive).
  HTTP/1.1 and HTTP/2 clients are served transparently on the same socket, HTTP/2 is
  negotiated by TLS ALPN (`h2`) or by the HTTP/2 connection preface. The transport lives in
  the separate `src/http2` module: see `iwn_http_server_spec::http2` and
  `iwn_http_request_is_http2()`. `iwn_wf` works with both transports unchanged
  (`iwn_wf_server_spec::http2`).
- iwn_wf: Fixed request path length after percent-decoding, `+` handling in request paths,
  malformed `%XX` escapes, unsupported HTTP method detection, `multipart/form-data` boundary
  parameter matching, uninitialized regexp submatch list, `NULL` dereference in
  `iwn_wf_request_submatch_last()`, a lock leak in `iwn_wf_session_put()` error path and the
  in-memory session store `clear` operation which did not drop stored data.
- Tests: Added in-process `iwn_wf` test coverage (route matching, request/query/header parsing,
  sessions, in-memory session store) and HTTP/2 runs of the HTTP server test cases.


# [v1.5.0] - 2026-11-04

- iwn_proc: Added `iwn_proc_spec::kill_process_group`: the child is started as a leader of its own
  session and process group, and all the process operations cover the whole process tree:
  `iwn_proc_kill()`, `iwn_proc_kill_all()` signal the process group, `iwn_proc_wait*()` complete
  only when the group is empty.
- iwn_proc: Fixed `iwn_proc_wait_timeout()` and `iwn_proc_wait_all_timeout()` which never timed out
  (the condition variable clock did not match the `iw_cond_timed_wait_ms()` deadline clock).
- Updated to iowow v1.7.3: fixed `iw_cond_timed_wait_ms()` deadline clock on platforms with
  `pthread_condattr_setclock()`.
- Tests: Added `poller_proc_test2` process group regression tests.

# [v1.4.2] - 2026-10-29

- grpc: Fixed busy-spin on exhausted HTTP/2 flow-control window, fixed client receive-path ordering, and added a flow-control regression test.
- grpc: Initial implementation of `iwn_grpc_server`
- grpc: Added per-invocation authorization header option.

# [v1.4.1] - 2026-10-22

- Updated to iowow v1.7.1: Fix of bad pthread spinlock detection.

# [v1.4.0] - 2026-10-19

- iwn_wf: Fixed wrong in-place body parsing.
- iwnet: Test cases refactored and migrated to iowow tests harness.
- src/http/iwn_http_server.c: Fixed errors in HTTP parser.
- src/grpc/iwn_grpc_client.c: Now tested in ssl mode.
- Autark: ENABLE_ASAN now works correctly.
- Autark: Project versions now track Changelog.
- src/Autark: macOS poller and shared-library builds - #11

# [v1.3.1] - 2026-09-08

- build.sh: updated

# [v1.3.0] - 2026-08-30

- fix: HTTP/1 state parser fixed and several memory errors.
- fix: Backported recent BearSSL fixes.
- impl: Migration on Autark build system.
- impl: Experimental gRPC client (iwn_grpc_client.h)
- chore: Bundle of CA Root Certificates updated (Thu Aug 13 03:12:01 2026 GMT)

# [v1.2.0] - 2025-07-19

- impl: Added printf helpers to iwn_curl.h
- misc: Migration to Autark build system.

# [v1.1.0] - 2024-04-16

- impl: Supported Unix domain sockets by WS/HTTP client/server
- fix: Used portable version of pthreads barrier (iowow/iwth.h)
- fix: Fixed wrong handling of fd error events (iwn_poller)
- impl: Implemened http proxy forwarding (iwn_http_server.h)
- impl: Added find_executable_in_path option in iwn_proc_spawn() (iwn_proc.c)
- impl: Added iwn_port_is_bound() (utils/iwn_net.h)
- impl: Added iwn_http_response_write_jbn() and iwn_http_response_write_jbl() (iwn_http_server.h)
- impl: Added iwn_wf_fileobj_serve() (iwn_wf_files.h)
- impl: Added iwn_url_encode_new_printf() (iwn_codec.h)
- fix: Fixed possible deadlock in _client_accept() (iwn_http_server.c)
- fix: Allow IPv6 server listening. (iwn_http_server.c)
- impl: Added iwn_poller_fd_is_managed() (iwn_poller.h)
- misc: Minors iwn_poller improvements.
- fix: FreeBSD build failed.
- fix: Endless loop in ws_server.c

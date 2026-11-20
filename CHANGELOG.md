# [v1.7.2] - 2026-11-20

- build: The iowow dependency is installed by the `iowow_build.sh` Autark check before the
  iwnet script is evaluated, because the iwnet build flags are resolved with
  `pkg-config libiowow`. Previously a build started from an empty cache failed with
  `Package libiowow was not found in the pkg-config search path` whenever the iowow
  dependency unit had not run yet; the cached `@@{}` output only hid the problem in
  incremental builds.

# [v1.7.1] - 2026-11-20

- tools: The `strliteral` and `mimegen` code generators are compiled by the host
  toolchain (`host-cc` rules, `run { host ... }`) instead of the target compiler, so
  iwnet can be cross compiled again. Before, a cross build linked the generators for
  the target and then failed to execute them (`./strliteral: Syntax error: word
  unexpected`) while generating `data_cacert.inc`.

# [v1.7.0] - 2026-11-20

- http: Fixed integer overflows of `Content-Length` values and hex chunk sizes in
  the HTTP/1.1 request parser. Both were accumulated in an `ssize_t` without a
  bounds check, so a long enough number wrapped to a negative body length. The
  body scanner then truncated that length to `int` and passed it to
  `_stream_jump()`, which moved the stream index *backwards* over already consumed
  bytes: an echo or body-storing handler returned bytes of an earlier request on
  the same connection buffer. Overflowing values are now rejected with
  `400 Bad Request` before the multiplication (`_length_accumulate()`), and
  `_stream_jump()` takes `ssize_t` and refuses negative offsets.
- http: A streamed (chunked or oversized) request body that the handler does not
  consume by `iwn_http_request_chunk_next()` no longer leaves the connection in a
  desynchronized state. `iwn_http_response_body_clear()` now resets the response
  body length, so an empty response no longer inherits the `content-length` of the
  previous response on the same connection, and such a connection is closed after
  the response instead of being reused (`HTTP_REQ_COMPLETE`). A request error
  detected after the response was already written closes the connection instead of
  appending a second (400) response to the same request.
- http: Duplicated `Content-Length` request headers are rejected with
  `400 Bad Request` (RFC 9112); previously the first header value was used
  silently. Error responses now always close the connection.
- http: A request carrying both `Transfer-Encoding` and `Content-Length` is
  rejected with `400 Bad Request` (RFC 9112 §6.1). Previously the message framing
  depended on the header order: `Content-Length` was used when it came first and
  the chunked framing when `Transfer-Encoding` came first, so intermediaries that
  resolve the ambiguity differently could be used for request smuggling.
- http: A `Transfer-Encoding` request field value is parsed as a transfer coding
  list (RFC 9112 §6.1) instead of matching the literal `chunked` text. A coding the
  server does not implement (`gzip`, `gzip, chunked`, a parameterized coding) is
  answered with `501 Not Implemented` instead of being silently ignored, while a
  repeated `chunked` coding or an empty field value is rejected with
  `400 Bad Request`. Case insensitive codings and optional whitespace around them
  are accepted (`Transfer-Encoding: chunked ` previously lost the chunked framing
  and silently dropped the request body).
- http: Request parser defects found by the new fuzzing harness:
  - a request without header fields (`GET / HTTP/1.0\r\n\r\n`) was rejected with
    `400 Bad Request`;
  - `Content-Length` with trailing whitespace was rejected, while an empty
    `Content-Length` value was accepted as `0`. The value must be digits with
    optional surrounding whitespace (RFC 9112 §6.3) now;
  - a header field name which is a prefix of `content-length` or
    `transfer-encoding` (for example `Conte: 5`) was treated as that field;
  - a chunk size line which does not start with a hex digit was silently ignored,
    the request body was decoded as empty instead of rejecting the request;
  - chunked trailer sections (RFC 9112 §7.1.2) were parsed as a part of the next
    chunk and rejected, they are parsed and ignored now;
  - a chunk extension containing whitespace (`3 ;ext=1`) was rejected, optional
    whitespace around a chunk extension is allowed (RFC 9112 §7.1.1) now;
  - a streamed request body larger than the buffer limit left the buffered stream
    in an inconsistent state (the emitted request body chunk pointed beyond the
    consumed stream length);
  - bytes of a pipelined request following a chunked request were consumed by the
    request parser. The parser stops at the end of the request now.
- http: The end of a streamed request body is reported to the chunk handler
  (`iwn_http_request_chunk_next()`) as `HS_TOK_REQ_END`, so the trailer section is
  parsed before the request handler is notified about the end of the body. This
  keeps the connection reusable for chunked requests.
- tests: Added the `http_parser1` regression test covering overflowing and non hex
  `Content-Length`/chunk sizes, duplicated `Content-Length` headers,
  `Content-Length` combined with `Transfer-Encoding`, transfer coding list values
  and streamed request bodies ignored by the handler
  (`src/http/tests/http_parser1.c`).
- fuzz: Added a fuzzy testing harness for the HTTP/1 request parser (`fuzz/`): a
  portable randomized `iwtests.h` driver (`fuzzdriver`) and a coverage guided
  libFuzzer target (`fuzzlib`). The parser is driven from memory by
  `iwn_http_request_parse_buf()`, the request framing is decoded independently and
  every input is checked for parser invariants (token bounds, body length
  bookkeeping, progress), framing semantics, determinism and truncated input
  handling. Enabled with `IWNET_BUILD_FUZZ=1`/`IWNET_RUN_FUZZ=1`, see
  `fuzz/README.md`.

# [v1.6.6] - 2026-11-19

- http2: Fixed a use-after-free when a deferred response write races connection
  teardown. `_conn_defer()` checked the connection state and scheduled a flush
  task (which takes a connection reference) without synchronization with
  `_conn_dispose()`; the flush task could then run with a freed connection.
  The state check, the queue append, the reference acquisition and the flush
  scheduling are now serialized by the leaf `out_mtx`, and `_conn_dispose()`
  clears `sess` under that lock before releasing the anchor reference.
  `conn->mtx` is deliberately not used there: the dispose path holds it while
  invoking the application request-dispose callback, so taking it from a
  response API would invert the lock order.
- ssl: The BearSSL and s2n adapters no longer use `iwn_poller_probe()` from
  their `arm`/`has_pending_write_bytes` callbacks. A probe takes and releases a
  poller slot reference; when it was the last reference, the slot and its
  connection were destroyed from inside `arm()`, recursively invoking the
  application request-dispose callback on a thread that was already flushing
  the connection. `arm()` now calls `iwn_poller_arm_events()` directly and the
  pending-write check locks the adapter mutex directly; both callbacks already
  have the adapter pointer.
- poller: `iwn_poller_poll_in_thread()` no longer destroys the start barrier
  while the poll thread may still be returning from `pthread_barrier_wait()`;
  the barrier is destroyed in `iwn_poller_destroy()` after the poll thread is
  joined.
- poller: `iwn_poller::stop` is an `atomic_bool`; the shutdown request and the
  poll loop no longer race on a plain `volatile bool`.

# [v1.6.5] - 2026-11-19

- http2: Fixed a race between connection teardown and a deferred response flush
  task. `_conn_dispose()` cleared `h2_conn::pa` and set the `closed`/`pa_closed`
  flags outside the connection mutex, while the flush task holds that mutex and
  uses `conn->pa` in the libhive send callback (`_hcb_send()`). A concurrent
  teardown could null the adapter pointer between its NULL check and the
  `conn->pa->write()` call, crashing the poller with a NULL dereference. The
  fields are now updated under `conn->mtx` (also in `_conn_on_event()`), so the
  flush task either finishes with a live adapter or skips the flush.

# [v1.6.4] - 2026-11-19

- build: `hive.h` is installed into the `--prefix` include directory when the
  HTTP/2 (`IWN_ENABLE_HTTP2`) or gRPC (`IWN_ENABLE_GRPC`) transport is enabled.
  Previously the header was only written into the iwnet build cache by libhive's
  `make install`, so an out-of-tree consumer of a nested iwnet build got
  `-I<prefix>/include` from `libiwnet.pc` but no `hive.h` there. This broke
  consumers that drive a libhive session directly (for example an HTTP/2
  client). `libhive.a` was already installed and is unchanged.

# [v1.6.3] - 2026-11-13

- poller: `iwn_poller_destroy()` stops the thread created by
  `iwn_poller_poll_in_thread()` before shutting down the worker pool. The poll
  thread could schedule one last event task after the pool shutdown started;
  such a task was never executed and leaked together with the connection state
  it referenced.

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

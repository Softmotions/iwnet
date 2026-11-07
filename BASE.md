# IWNET

Pure `C` asynchronous HTTP framework providing websockets client/server, SSL, reverse proxy and routing.

Works on Linux, macOS, FreeBSD

* [Fast asynchronous HTTP server](./src/http) ([iwn_http_server.h](./src/http/iwn_http_server.h))
* [Web framework based on HTTP server](./src/http) ([iwn_wf.h](./src/http/iwn_wf.h))   
* Optional HTTP/2 server transport for HTTP server and web framework ([src/http2](./src/http2))
* Ultra fast HTTP Reverse Proxy ([iwn_http_server.h](./src/http/iwn_http_server.h))
* Websocket client and server ([iwn_ws_server.h](./src/ws/iwn_ws_server.h), [iwn_ws_client.h](./src/ws/iwn_ws_client.h))
* Low level gRPC client with no dependency on `libgrpc++` or other grpc staff. [iwn_grpc_client.h](./src/grpc/iwn_grpc_client.h)
* Low level gRPC server with no dependency on `libgrpc++` or other grpc staff. [iwn_grpc_server.h](./src/grpc/iwn_grpc_server.h)
* Poller reactor ([iwn_poller.h](./src/poller/iwn_poller.h))
* TLS layer with selectable backends ([iwn_tls.h](./src/ssl/iwn_tls.h), [iwn_tls_poller_adapter.h](./src/ssl/iwn_tls_poller_adapter.h))
* Manager of child processes ([iwn_proc.h](./src/poller/iwn_proc.h))
* Timer ([iwn_scheduler.h](./src/poller/iwn_scheduler.h))

## Build options

Build options are set as environment variables, for example:

```sh
IWN_ENABLE_GRPC=1 IWN_ENABLE_S2N=1 BUILD_TYPE=Debug ./build.sh -c
```

| Option                     | Default   | Meaning                                                                                  |
| -------------------------- | --------- | ---------------------------------------------------------------------------------------- |
| `IWN_ENABLE_GRPC`          | `0`       | Build the gRPC server/client (requires libhive).                                          |
| `IWN_ENABLE_HTTP2`         | `0`       | Build the HTTP/2 server transport (requires libhive).                                     |
| `IWN_ENABLE_S2N`           | `0`       | Build the AWS s2n-tls TLS backend (fetched and compiled, needs `cmake` + OpenSSL `libcrypto`). |
| `IWNET_BUILD_SHARED_LIBS`  | `0`       | Also build `libiwnet` as a shared library.                                                |
| `IWNET_BUILD_TESTS`        | `0`       | Build the test cases.                                                                     |
| `IWNET_RUN_TESTS`          | `0`       | Build and run the test cases.                                                             |
| `ENABLE_ASAN`              | `0`       | Build with the AddressSanitizer.                                                          |
| `ENABLE_UBSAN`             | `0`       | Build with the UndefinedBehaviorSanitizer.                                                |
| `ENABLE_DEBINFO`           | `0`       | Keep debug information in a `Release` build.                                              |
| `BUILD_TYPE`               | `Release` | `Release` or `Debug` build. `Debug` uses `-O0`, enables assertions and `-Werror`.         |
| `CC`                       | auto      | C compiler (`clang` is preferred, it enables the optional blocks API).                    |

The external dependency sources can be overridden with `IOWOW_URL`, `LIBHIVE_URL` and
`IWN_S2N_URL` (each defaults to a pinned upstream release). A complete list of the
available options is printed by:

```sh
./build.sh -l
```

## TLS implementations

TLS connections are handled by a selectable backend (`iwn_tls_impl_e`):

* `IWN_TLS_IMPL_BEARSSL` — BearSSL, TLS 1.2, no external dependencies. This is the default.
* `IWN_TLS_IMPL_S2N` — [AWS s2n-tls](https://github.com/aws/s2n-tls), TLS 1.2 and TLS 1.3.

s2n-tls support is optional and enabled with `IWN_ENABLE_S2N=1`. The build fetches and
compiles a pinned s2n-tls release, so `cmake` and OpenSSL `libcrypto` development files
are required:

```sh
  IWN_ENABLE_S2N=1 ./build.sh -c
```

The backend is selected per server/client with the `tls_impl` field of
`iwn_http_server_ssl_spec`, `iwn_grpc_server_spec::ssl`, `iwn_grpc_client_spec::ssl`
and `iwn_ws_client_spec`. The zero value (and the default when the field is not set)
is `IWN_TLS_IMPL_BEARSSL`.

```c
struct iwn_http_server_ssl_spec ssl = {
  .certs = "server-cert.pem",
  .private_key = "server-key.pem",
  .certs_len = -1,
  .private_key_len = -1,
  .tls_impl = IWN_TLS_IMPL_S2N,
};
```

Use `iwn_tls_impl_available()` to check whether the requested backend is compiled in.

## Build from sources

**Prerequisites**

* Linux, macOS or FreeBSD
* gcc or clang compiler (clang is preferred since allows code blocks API provided by this project)
* pkgconf or pkg-config

Builds powerd by [Autark](https://github.com/Softmotions/autark)

```sh
./build.sh
```

**Installation**

```sh
./build.sh --prefix=$HOME/.local
```

**Tests**

The test cases are built and run by:

```sh
IWNET_RUN_TESTS=1 ./build.sh -c

# Run only the cases whose name contains "echo" or "multipart"
IW_TEST_FILTER=echo,multipart IWNET_RUN_TESTS=1 ./build.sh -c
```

The C test cases are [iwtests.h](./src/iwtests.h) suites, see [TESTS.md](./TESTS.md)
for the harness documentation and the project specific test layout.

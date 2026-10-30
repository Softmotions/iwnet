# IWNET

Pure `C` asynchronous HTTP framework providing websockets client/server, SSL, reverse proxy and routing.

Works on Linux, macOS, FreeBSD

* [Fast asynchronous HTTP server](./src/http) ([iwn_http_server.h](./src/http/iwn_http_server.h))
* [Web framework based on HTTP server](./src/http) ([iwn_wf.h](./src/http/iwn_wf.h))   
* Ultra fast HTTP Reverse Proxy ([iwn_http_server.h](./src/http/iwn_http_server.h))
* Websocket client and server ([iwn_ws_server.h](./src/ws/iwn_ws_server.h), [iwn_ws_client.h](./src/ws/iwn_ws_client.h))
* Low level gRPC client with no dependency on `libgrpc++` or other grpc staff. [iwn_grpc_client.h](./src/grpc/iwn_grpc_client.h)
* Low level gRPC server with no dependency on `libgrpc++` or other grpc staff. [iwn_grpc_server.h](./src/grpc/iwn_grpc_server.h)
* Poller reactor ([iwn_poller.h](./src/poller/iwn_poller.h))
* SSL Layer is based on BearSSL ([iwn_brssl_poller_adapter.h](./src/ssl/iwn_brssl_poller_adapter.h))
* Manager of child processes ([iwn_proc.h](./src/poller/iwn_proc.h))
* Timer ([iwn_scheduler.h](./src/poller/iwn_scheduler.h))

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



# Asynchronous HTTP Framework

## Examples
### Simple echo server

```sh
  ./echo_http_server --ssl
 
  curl -k -XPUT -d'Hello' https://localhost:8080/echo
  Hello
  I'm an echo web server
```

echo_http_server.c

```c
#include "iwn_wf.h"

#include <iowow/iwconv.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <errno.h>

static struct iwn_poller *poller;
static struct iwn_wf_ctx *ctx;

static void _on_signal(int signo) {
  fprintf(stderr, "\nExiting...\n");
  iwn_poller_shutdown_request(poller);
}

static int _handle_echo(struct iwn_wf_req *req, void *user_data) {
  fprintf(stderr, "Echo handler called\n");
  iwn_http_response_printf(req->http, 200, "text/plain", "%.*s\n%s\n",
                           (int) req->body_len, req->body, (char*) user_data);
  return IWN_WF_RES_PROCESSED;
}

int main(int argc, char *argv[]) {
  signal(SIGPIPE, SIG_IGN);
  if (  signal(SIGTERM, _on_signal) == SIG_ERR
     || signal(SIGINT, _on_signal) == SIG_ERR) {
    return EXIT_FAILURE;
  }

  iwrc rc = 0;
  bool ssl = false;
  int port = 8080;

  for (int i = 1; i < argc; ++i) {
    if (strcmp(argv[i], "--ssl") == 0) {
      ssl = true;
    } else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
      port = iwatoi(argv[i + 1]);
    }
  }
  RCC(rc, finish, iw_init());              // Init iowow runtime, logging, etc..
  RCC(rc, finish, iwn_wf_create(0, &ctx)); // Create web server context
  RCC(rc, finish, iwn_wf_route(&(struct iwn_wf_route) {
    .ctx = ctx,
    .pattern = "/echo",
    .handler = _handle_echo,
    .user_data = "I'm an echo web server",
    .flags = IWN_WF_PUT | IWN_WF_POST
  }, 0));

  RCC(rc, finish, iwn_poller_create(0, 0, &poller));

  struct iwn_wf_server_spec spec = {
    .listen = "localhost",
    .port   = port,
    .poller = poller,
  };
  if (ssl) {
    spec.ssl.private_key = "./server-eckey.pem";
    spec.ssl.private_key_len = -1;
    spec.ssl.certs = "./server-ecdsacert.pem";
    spec.ssl.certs_len = -1;
  }

  // Print out a routes configuration.
  iwn_wf_route_print(ctx->root, stderr);
  // Configure HTTP server.
  RCC(rc, finish, iwn_wf_server(&spec, ctx));
  fprintf(stderr,
          "\nOpen terminal and run:\n\tcurl -k -XPUT -d'Hello' %s://%s:%d\n",
          (ssl ? "https" : "http"),
          spec.listen,
          spec.port);

  // Start fds poller reactor.
  iwn_poller_poll(poller);

finish:
  iwn_poller_destroy(&poller);
  if (rc) {
    iwlog_ecode_error3(rc);
    return EXIT_FAILURE;
  } else {
    return EXIT_SUCCESS;
  }
}
```

### Todo list REST API server

[todolist_http_server.c](https://github.com/Softmotions/iwnet/tree/master/src/http/examples/todolist_http_server.c)

```sh
./todolist_http_server --ssl
0001 [root:*] 
0002   [/todo> ALL
0003     {create:/([a-zA-z]+[a-z0-9A-Z]*)] PUT
0004     {get:/([0-9]+)] GET
0005     {remove:/([0-9]+)] DELETE
0006     [list:*] GET
0007     [done:*] POST

 Create a new 'Hello' todo entry:
	curl -k -XPUT -d'Say Hello' https://localhost:8080/todo/Hello
	curl -k -XPUT -d'Say Hello' https://localhost:8080/todo/Hello?done=1

 List all todo list items:
	curl -k https://localhost:8080/todo

 Get task #1 details:
	curl -k https://localhost:8080/todo/1

 Remove task #2 from todo list:
	curl -k -XDELETE https://localhost:8080/todo/2

 Update done status of task #2:
	curl -k -XPOST -d'id=2&done=1' https://localhost:8080/todo
```

### More examples 

You may find many helpful code examples by looking into 
[framework test code](https://github.com/Softmotions/iwnet/tree/master/src/http/tests)

* [server2.c](https://github.com/Softmotions/iwnet/tree/master/src/http/tests/server2.c)
* [server1.c](https://github.com/Softmotions/iwnet/tree/master/src/http/tests/server1.c)
* [HTTP Proxy: proxy1.c](https://github.com/Softmotions/iwnet/tree/master/src/http/tests/proxy1.c)



# gRPC client and server

Lightweight asynchronous gRPC client and server for C built on top of HTTP/2 and the iwnet poller infrastructure.
This is a low level API that operates on already serialized Protocol Buffers messages and does not require generated
protobuf stubs. The module is experimental at this time and needs more testing.

## Features

- Unary RPC
- Server streaming
- Client streaming
- Bidirectional streaming
- Low level gRPC server with request dispatch by service path
- TLS with ALPN
- Plaintext HTTP/2 connections
- UNIX domain sockets
- gRPC message compression negotiation
- gRPC status and error handling
- Asynchronous operation using `iwn_poller`
- Request cancellation
- Multiple concurrent HTTP/2 streams

## How to enable iwnet gRPC

Turn ON `ENABLE_GRPC` flag.

```sh
ENABLE_GRPC=1 .. ./build.sh ...
```

Call `iwn_grpc_init()` once before using the client or the server.

## Connection URLs

Supported URL schemes:

```text
grpc://host[:port]
grpc+plaintext://host[:port]
grpc+socket:///path/to/socket
```

`grpc://` establishes a TLS connection. For a server, the TLS certificate and private key are configured with
`iwn_grpc_server_spec::ssl`.

The client uses ports `443` and `80` by default. The server listens on port `50051` by default.

## Client

### Opening a client

```c
struct iwn_grpc_client_spec spec = {
  .url = "grpc+plaintext://localhost:50051",
  .poller = poller,
  .on_handshake = on_handshake,
  .on_closed = on_closed,
  .on_error = on_error,
  .on_destroy = on_destroy,
};

struct iwn_grpc_client *client = 0;

iwrc rc = iwn_grpc_client_open(&spec, &client);
```

### Opening a request

Request messages are passed as serialized protobuf data using `struct iwn_val`.

```c
struct iwn_grpc_req_spec spec = {
  .client = client,
  .path = "/helloworld.Greeter/SayHello",
  .on_message = on_message,
  .on_error = on_request_error,
  .on_closed = on_request_closed,
  .on_destroy = on_request_destroy,
};

struct iwn_val msg = {
  .buf = protobuf_data,
  .len = protobuf_data_len,
};

uint32_t req_id;

iwrc rc = iwn_grpc_client_request_open(
  &spec,
  &msg,
  0,       // identity encoding
  &req_id);
```

The message data is copied internally before the function returns. Ownership of the supplied `struct iwn_val` and its
buffer remains with the caller. Incoming protobuf messages are delivered through:

```c
void (*on_message)(struct iwn_grpc_req_message*, bool *out_continue);
```

The client does not decode protobuf messages.

### Authorization

The `authorization` HTTP/2 header can be set for the whole client:

```c
struct iwn_grpc_client_spec spec = {
  .url = "grpc://api.example.com",
  .poller = poller,
  .authorization = "Bearer <token>",
  ...
};
```

or per request, overriding the client value:

```c
struct iwn_grpc_req_spec spec = {
  .client = client,
  .path = "/grpc.example.Service/Method",
  .authorization = "Bearer <token>",
  ...
};
```

Per-request authorization is used when the credential is obtained after the client connection is established
(for example by an authentication RPC) or when it is renewed during the session lifetime. The value is copied before
`iwn_grpc_client_request_open()` returns.

### Streaming messages

Enable client-side streaming with:

```c
struct iwn_grpc_req_spec spec = {
  .client = client,
  .path = "/helloworld.Greeter/SayHelloBidiStream",
  .client_streaming = true,
  ...
};
```

Additional messages can then be queued with:

```c
iwn_grpc_client_stream_next_message(ctx, &msg, false);
```

Send the final message with:

```c
iwn_grpc_client_stream_next_message(ctx, &msg, true);
```

The `stop_streaming` argument closes the client-to-server side of the gRPC stream after the queued message has been sent.
`on_outgoing_messages_queue_drained` is called whenever the outgoing message queue becomes empty.

### Request contexts

A request can be accessed asynchronously by its HTTP/2 stream ID:

```c
struct iwn_grpc_req_ctx ctx;

if (iwn_grpc_client_acquire_request_ctx(client, req_id, &ctx)) {
  // Use ctx.
  ...
  iwn_grpc_client_release_request_ctx(&ctx);
}
```

Every successfully acquired request context must be released.
To cancel an active request:

```c
iwn_grpc_client_request_cancel(&ctx);
```

This terminates the HTTP/2 stream with `RST_STREAM(CANCEL)`.

### Closing the client

```c
iwn_grpc_client_close(client);
```

The shutdown is asynchronous. `on_closed` is called when the network connection has been closed, and `on_destroy` is
called immediately before the client and its resources are destroyed.

After the client has been destroyed, all client and request handles are invalid.

## Server

### Opening a server

```c
static iwrc on_request(struct iwn_grpc_server_req *req) {
  if (!req->path || strcmp(req->path, "/helloworld.Greeter/SayHello") != 0) {
    return GRPC_ERROR_UNIMPLEMENTED;
  }
  return 0;
}

static void on_message(struct iwn_grpc_server_msg *msg, bool *out_continue) {
  iwrc rc = iwn_grpc_server_req_write_message(msg->req, &msg->msg, msg->compressed);
  if (rc) {
    *out_continue = false;
  }
}

static void on_request_end(struct iwn_grpc_server_req *req) {
  iwn_grpc_server_req_end(req, 0, 0);
}

struct iwn_grpc_server_spec spec = {
  .url = "grpc+plaintext://0.0.0.0:50051",
  .poller = poller,
  .on_request = on_request,
  .on_message = on_message,
  .on_request_end = on_request_end,
};

struct iwn_grpc_server *server = 0;

iwrc rc = iwn_grpc_server_open(&spec, &server);
```

A plaintext server example is shown above. For `grpc://` the TLS settings are required:

```c
struct iwn_grpc_server_spec spec = {
  .url = "grpc://0.0.0.0:50051",
  .poller = poller,
  .ssl = {
    .certs = "server-cert.pem",
    .private_key = "server-key.pem",
    .certs_len = -1,       // strlen()
    .private_key_len = -1, // strlen()
  },
  ...
};
```

PEM data can be passed directly with `certs_in_buffer = true` / `private_key_in_buffer = true`.

Server defaults:

- `grpc.max_message_bytes` — `1048576`
- `grpc.max_concurrent_streams` — `256`
- `grpc.accept_encoding` — `identity`
- `flags` — `0`; set `IWN_GRPC_LOG_QUIET` to reduce connection logging.

### Request callbacks

```c
iwrc (*on_request)(struct iwn_grpc_server_req*);
void (*on_message)(struct iwn_grpc_server_msg*, bool *out_continue);
void (*on_request_end)(struct iwn_grpc_server_req*);
void (*on_request_closed)(const struct iwn_grpc_server_req*);
void (*on_request_destroy)(const struct iwn_grpc_server_req*);
```

- `on_request` is called when the request headers are received. The handler dispatches by `req->path`.
  Returning a non zero `iwrc` finishes the request with the corresponding gRPC status.
- `on_message` is called for every incoming message. Set `out_continue` to `false` to stop delivering further
  request messages. Messages are delivered in their original compressed form; `msg->compressed` and
  `req->data_encoding` describe the payload.
- `on_request_end` is called when the client side of the request stream is closed.
- `on_request_closed` is called when the request stream is closed.
- `on_request_destroy` is called before the request and its resources are destroyed.

Request fields:

```c
struct iwn_grpc_server_req {
  iwrc rc;
  struct iwn_grpc_server_conn_ctx conn_ctx;
  const char *path;          // :path
  const char *authority;     // :authority
  const char *method;        // :method
  const char *content_type;  // content-type
  const char *authorization; // authorization
  const char *data_encoding; // grpc-encoding
  uint32_t stream_id;
  void *user_data;           // Free for handler state
  void *impl;
};
```

`req->user_data` is the place to keep per-request handler state. Free it in `on_request_destroy`.

The request handle is valid only while the request is alive. Use
`iwn_grpc_server_req_ref()` / `iwn_grpc_server_req_unref()` if the handle has to be retained beyond a callback.

### Sending a response

Response headers are sent automatically by the first `iwn_grpc_server_req_write_message()` call using
`identity` encoding. To use another response encoding, write the headers explicitly first:

```c
iwn_grpc_server_req_write_headers(req, "gzip");
```

Queue response messages:

```c
struct iwn_val msg = {
  .buf = protobuf_data,
  .len = protobuf_data_len,
};

iwn_grpc_server_req_write_message(req, &msg, false);
```

The message is copied before the function returns. The `compressed` argument sets the gRPC per-message compressed flag.

Finish the response:

```c
iwn_grpc_server_req_end(req, 0, 0);
```

Queued messages are sent before the gRPC trailers. If neither response headers nor messages were written,
`iwn_grpc_server_req_end()` produces a trailers-only response.

To report an error, pass an `iwrc` error code and an optional message:

```c
iwn_grpc_server_req_end(req, GRPC_ERROR_NOT_FOUND, "not found");
```

The error code is mapped to a gRPC status, and `message` is sent as a percent-encoded `grpc-message` trailer.

To abort the stream immediately:

```c
iwn_grpc_server_req_cancel(req);
```

This terminates the HTTP/2 stream with `RST_STREAM(CANCEL)`.

### RPC modes

The same response API implements all gRPC modes:

| Mode | Server implementation |
|---|---|
| Unary | Reply in `on_message`, finish in `on_request_end`. |
| Server streaming | Write several messages in `on_request_end`, then call `iwn_grpc_server_req_end()`. |
| Client streaming | Accumulate request messages in `on_message`, reply once in `on_request_end`. |
| Bidirectional streaming | Reply from `on_message` and finish in `on_request_end`. |

The server does not decode protobuf messages.

### Connection and server callbacks

```c
void (*on_closed)(struct iwn_grpc_server_conn_ctx*);
void (*on_error)(struct iwn_grpc_server_conn_ctx*);
void (*on_destroy)(struct iwn_grpc_server_ctx*);
```

- `on_closed` is called when a network connection is closed. It is called after the `on_request_closed` callbacks of
  the requests belonging to that connection.
- `on_error` is called on a generic HTTP/2 session error. The error is available as `ctx->rc`.
- `on_destroy` is called before the server and its resources are destroyed.

### Closing the server

```c
iwn_grpc_server_close(server);
```

The shutdown is asynchronous. The listener is closed and active connections receive `GOAWAY`. `on_destroy` is called
before the server and its resources are destroyed.

### Clang blocks

Every client and server callback has a block counterpart enabled when the compiler supports blocks
(`IW_BLOCKS`). For example:

```c
struct iwn_grpc_server_spec spec = {
  .url = "grpc+plaintext://0.0.0.0:50051",
  .poller = poller,
  .on_request_block = ^iwrc(struct iwn_grpc_server_req *req) {
    return 0;
  },
  .on_request_end_block = ^(struct iwn_grpc_server_req *req) {
    iwn_grpc_server_req_end(req, 0, 0);
  },
  ...
};
```

## Errors

Request-level client errors are reported through:

```c
iwn_grpc_req_spec.on_error
```

The request context contains:

```c
ctx->rc
ctx->error_explained
```

Connection and HTTP/2 session errors are reported through:

```c
iwn_grpc_client_spec.on_error
iwn_grpc_server_spec.on_error
```

gRPC status codes are mapped to `GRPC_ERROR_*` values defined in `iwn_grpc.h`.

# License

```

MIT License

Copyright (c) 2012-2026 Softmotions Ltd <info@softmotions.com>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

```


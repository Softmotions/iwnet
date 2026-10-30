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

# gRPC client

Lightweight asynchronous gRPC client for C built on top of HTTP/2 and the iwnet poller infrastructure. This is a low
level client API what operates on already serialized Protocol Buffers messages and does not require generated protobuf
stubs. This module is experimental at this time, need more testing.

## Features

- Unary RPC
- Server streaming
- Client streaming
- Bidirectional streaming
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

## Connection URLs

Supported URL schemes:

```text
grpc://host[:port]
grpc+plaintext://host[:port]
grpc+socket:///path/to/socket
```

`grpc://` establishes a TLS connection.

Example:

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

Call `iwn_grpc_init()` once before using the gRPC client.

## Opening a request

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

## Streaming messages

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

## Request contexts

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

## Closing the gRPC client

```c
iwn_grpc_client_close(client);
```

The shutdown is asynchronous. `on_closed` is called when the network connection has been closed, and `on_destroy` is
called immediately before the client and its resources are destroyed.

After the client has been destroyed, all client and request handles are invalid.

## Errors

Request-level gRPC errors are reported through:

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
```

gRPC status codes are mapped to `GRPC_ERROR_*` values defined in `iwn_grpc.h`.

## Tests

Examples covering the supported RPC modes are located in:

```text
src/grpc/tests/grpc_test_client1.c   Unary RPC
src/grpc/tests/grpc_test_client2.c   Server streaming
src/grpc/tests/grpc_test_client3.c   Bidirectional streaming
```

The accompanying Python test server is:

```text
src/grpc/tests/grpc_test_server1.py
```

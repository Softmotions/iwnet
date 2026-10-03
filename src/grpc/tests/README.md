## Tests

Examples covering the supported RPC modes are located in:

```text
src/grpc/tests/grpc_test_client1.c   Unary RPC
src/grpc/tests/grpc_test_client2.c   Server streaming
src/grpc/tests/grpc_test_client3.c   Bidirectional streaming
src/grpc/tests/grpc_test_client4.c   Split/packed gRPC frame parsing
src/grpc/tests/grpc_test_client5.c   gRPC error status propagation
src/grpc/tests/grpc_test_client6.c   Request cancellation
src/grpc/tests/grpc_test_client7.c   Concurrent requests
```

The accompanying Python test servers are:

```text
src/grpc/tests/grpc_test_server1.py
src/grpc/tests/grpc_mock.py
```

The test server and all test clients accept a `--port PORT` option (default `50051`)
and a `--ssl` option. The TLS test server uses `grpc-server-cert.pem` and
`grpc-server-key.pem`; regenerate them with `gen-certs.sh` when necessary.

To run the whole suite, including automatic server startup and shutdown:

```sh
src/grpc/tests/tests.sh [--port PORT] [--ssl]
```

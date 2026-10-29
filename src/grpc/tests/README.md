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
grpc_test_client8.c   Per-request authorization header
```

The accompanying Python test servers are:

```text
src/grpc/tests/grpc_test_server1.py
src/grpc/tests/grpc_mock.py
```

The test server accepts a `--port PORT` option (default `50051`) and a `--ssl`
option. The TLS test server uses `grpc-server-cert.pem` and
`grpc-server-key.pem`; regenerate them with `gen-certs.sh` when necessary.

The test clients are `iwtests.h` suites, their options are passed after `--`,
which stops the option parsing of the test harness:

```sh
./grpc_test_client1 -- --port 50051 --ssl
src/grpc/tests/tests.sh [--port PORT] [--ssl]
```

See [TESTS.md](../../../TESTS.md) for the test harness documentation.

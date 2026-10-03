#!/usr/bin/env sh

set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"

PORT="${GRPC_TEST_PORT:-50051}"
BIN_DIR="${GRPC_TEST_BIN_DIR:-}"
PYTHON="${PYTHON:-python3}"
USE_SSL=0

usage() {
  cat <<EOF
Usage: $0 [--port PORT] [--bin-dir DIR] [--ssl]

Runs the iwnet gRPC client test suite. Starts the Python test server,
runs grpc_test_client{1,2,3} against it and shuts the server down on exit.

Options:
  --port, -p PORT   Port used by the server and clients (default: 50051).
  --bin-dir DIR     Directory containing grpc_test_client{1,2,3} binaries.
  --ssl             Run clients and server in TLS mode.
  -h, --help        Show this help.

Environment:
  GRPC_TEST_PORT     Default port (overridden by --port).
  GRPC_TEST_BIN_DIR  Directory with test binaries (overridden by --bin-dir).
  PYTHON             Python interpreter used to run the server.
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --port|-p)
      [ $# -ge 2 ] || {
        echo "Missing value for $1" >&2
        exit 1
      }
      PORT="$2"
      shift 2
      ;;
    --bin-dir)
      [ $# -ge 2 ] || {
        echo "Missing value for $1" >&2
        exit 1
      }
      BIN_DIR="$2"
      shift 2
      ;;
    --ssl)
      USE_SSL=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage
      exit 1
      ;;
  esac
done

case "$PORT" in
  ''|*[!0-9]*)
    echo "Invalid port: $PORT" >&2
    exit 1
    ;;
esac

if [ "$PORT" -lt 1 ] || [ "$PORT" -gt 65535 ]; then
  echo "Invalid port: $PORT" >&2
  exit 1
fi

find_root() {
  _dir="$1"
  while [ "$_dir" != "/" ]; do
    if [ -f "$_dir/build.sh" ]; then
      printf '%s\n' "$_dir"
      return 0
    fi
    _dir="$(dirname "$_dir")"
  done
  return 1
}

ROOT_DIR="$(find_root "$SCRIPT_DIR" || true)"

if [ -z "$BIN_DIR" ]; then
  for _dir in "$PWD" "$SCRIPT_DIR" "${ROOT_DIR:+$ROOT_DIR/autark-cache/src/grpc/tests}"; do
    if [ -x "$_dir/grpc_test_client1" ]; then
      BIN_DIR="$_dir"
      break
    fi
  done
fi

if [ -z "$BIN_DIR" ]; then
  echo "Cannot locate gRPC test binaries." >&2
  echo "Build the tests first, for example:" >&2
  echo "  ENABLE_GRPC=1 IWNET_BUILD_TESTS=1 ./build.sh" >&2
  echo "or pass --bin-dir." >&2
  exit 1
fi

BIN_DIR="$(cd "$BIN_DIR" && pwd)"

for _bin in grpc_test_client1 grpc_test_client2 grpc_test_client3; do
  if [ ! -x "$BIN_DIR/$_bin" ]; then
    echo "Missing test binary: $BIN_DIR/$_bin" >&2
    exit 1
  fi
done

if [ -f "$SCRIPT_DIR/grpc_test_server1.py" ]; then
  SERVER_DIR="$SCRIPT_DIR"
else
  SERVER_DIR="${ROOT_DIR:+$ROOT_DIR/src/grpc/tests}"
fi

if [ ! -f "$SERVER_DIR/grpc_test_server1.py" ]; then
  echo "Cannot locate grpc_test_server1.py" >&2
  exit 1
fi

SERVER_DIR="$(cd "$SERVER_DIR" && pwd)"

if [ "$USE_SSL" -eq 1 ]; then
  for _f in grpc-server-cert.pem grpc-server-key.pem; do
    if [ ! -f "$SERVER_DIR/$_f" ]; then
      echo "Cannot locate TLS file: $SERVER_DIR/$_f" >&2
      exit 1
    fi
  done
fi

SERVER_PID=""

cleanup() {
  trap - EXIT INT TERM
  if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
    echo "Stopping gRPC test server (pid $SERVER_PID)..." >&2
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

if ! command -v "$PYTHON" >/dev/null 2>&1; then
  echo "Python interpreter not found: $PYTHON" >&2
  exit 1
fi

SERVER_ARGS="--port $PORT"
CLIENT_ARGS="--port $PORT"
if [ "$USE_SSL" -eq 1 ]; then
  SERVER_ARGS="$SERVER_ARGS --ssl"
  CLIENT_ARGS="$CLIENT_ARGS --ssl"
fi

if [ "$USE_SSL" -eq 1 ]; then
  echo "Starting gRPC test server in SSL mode on 127.0.0.1:$PORT..."
else
  echo "Starting gRPC test server in plaintext mode on 127.0.0.1:$PORT..."
fi
(
  cd "$SERVER_DIR"
  exec "$PYTHON" grpc_test_server1.py $SERVER_ARGS
) &
SERVER_PID=$!

"$PYTHON" - "$PORT" <<'PY'
import socket
import sys
import time

port = int(sys.argv[1])
deadline = time.time() + 15.0
while time.time() < deadline:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=1.0):
            sys.exit(0)
    except OSError:
        time.sleep(0.1)

print(f"gRPC test server did not become ready on port {port}", file=sys.stderr)
sys.exit(1)
PY

if ! kill -0 "$SERVER_PID" 2>/dev/null; then
  echo "gRPC test server exited before becoming ready." >&2
  wait "$SERVER_PID" 2>/dev/null || true
  exit 1
fi

for _bin in grpc_test_client1 grpc_test_client2 grpc_test_client3; do
  echo "Running $_bin..."
  "$BIN_DIR/$_bin" $CLIENT_ARGS
done

echo "All gRPC tests passed."

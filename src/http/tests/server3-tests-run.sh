#!/usr/bin/env sh
#
# Tests runtime TLS switch-over of the HTTP server (`iwn_http_server_ssl_set()`).
#
# The server starts in the plain text mode and switches to TLS and back several
# times, while HTTP requests are issued after every switch. Each switch replaces
# the TLS settings shared by all server connections, so this also proves that
# settings still borrowed by connections in flight are not freed prematurely.

set -e

PORT=9393
VALGRIND=""

while [ $# -gt 0 ]; do
  case $1 in
    --valgrind)
      VALGRIND=1
      shift
      ;;
    --port)
      shift
      PORT="$1"
      shift
      ;;
    *)
      shift
      ;;
  esac
done

FIFO="./server3.cmd.fifo"
LOG="./server3.log"
rm -f "${FIFO}" "${LOG}"
mkfifo "${FIFO}"

SERVER="./server3 --port ${PORT}"
if [ -n "${VALGRIND}" ]; then
  SERVER="valgrind --leak-check=full --errors-for-leak-kinds=definite --error-exitcode=9 ${SERVER}"
fi

echo "Command: ${SERVER}"
${SERVER} < "${FIFO}" 2> "${LOG}" &
SPID="$!"
exec 3> "${FIFO}"

cmd() {
  echo "$1" >&3
}

# Requests `url` until the server answers it, which means the requested protocol
# mode is applied.
probe() {
  url="$1"
  i=0
  while [ $i -lt 100 ]; do
    if curl -fsSk --max-time 2 -o /dev/null "${url}" 2>/dev/null; then
      printf "  %s: ok\n" "${url}"
      return 0
    fi
    i=$((i + 1))
    sleep 0.1
  done
  printf "Failed to get a response from %s\n" "${url}"
  cat "${LOG}"
  exit 1
}

BASE="http://localhost:${PORT}"
SECURE="https://localhost:${PORT}"

printf "Plain text mode:\n"
probe "${BASE}/"

printf "Switch to TLS:\n"
cmd "secure"
probe "${SECURE}/"
probe "${SECURE}/"

printf "Switch back to plain text:\n"
cmd "plain"
probe "${BASE}/"

printf "Switch to TLS again:\n"
cmd "secure"
probe "${SECURE}/"

printf "Reload TLS settings with the same certificates:\n"
cmd "secure"
probe "${SECURE}/"

printf "Disable TLS:\n"
cmd "plain"
probe "${BASE}/"

cmd "quit"
exec 3>&-
wait ${SPID}

if [ -n "${VALGRIND}" ] && [ "${IWN_TEST_TLS}" != "s2n" ]; then
  # s2n-tls keeps the process global state allocated by `s2n_init()`,
  # so the leak check is applicable to the BearSSL implementation only.
  grep -q "All heap blocks were freed" "${LOG}"
fi

printf "\nDone!\n"

#!/usr/bin/env sh
#
# End-to-end tests of the test HTTP server.
#
# The `--http2` option starts the server with
# `iwn_http_server_spec::http2`/`iwn_wf_server_spec::http2` enabled and runs
# the very same set of requests over HTTP/2. Plain text connections use the
# HTTP/2 connection preface (`curl --http2-prior-knowledge`), TLS connections
# use ALPN (`curl --http2`). Tests run twice: over HTTP/1.1 and over HTTP/2,
# which proves that the server negotiates both transports transparently.
# Requests that use HTTP/1.1 specific features (`Connection`, `Transfer-Encoding`)
# are skipped in the HTTP/2 mode.

set -e

SOPTS=""
PORT=9292
PROTO="http"
HTTP2=""

while [ $# -gt 0 ]; do
  case $1 in
    --valgrind)
      VALGRIND=1
      shift
      ;;
    --http2)
      HTTP2=1
      SOPTS="${SOPTS} --http2"
      shift
      ;;
    --port)
      shift
      PORT="$1"
      SOPTS="${SOPTS} --port ${PORT}"
      shift
      ;;
    --)      
      shift
      SOPTS="${SOPTS} $@"
      break
      ;;
    *)
      shift
      ;;
  esac
done

if [ -z "${PORT}" ]; then
  echo "Invalid --port specified"
  exit 1
fi

if echo "${SOPTS}" | grep '\-\-ssl'; then
  PROTO="https"
fi

# HTTP/2 is negotiated by ALPN over TLS and by the connection
# preface (prior knowledge) over plain text connections.
CURLOPTS=""
LOG="server1"
if [ -n "${HTTP2}" ]; then
  LOG="server1-h2"
  if [ "${PROTO}" = "https" ]; then
    CURLOPTS="--http2"
  else
    CURLOPTS="--http2-prior-knowledge"
  fi
fi

run() {

  sleep 1

  BASE="${PROTO}://localhost:${PORT}"
  FILTER='sed -E /(date|user-agent|trying|tcp)|^\*/Id'

  printf "\n\nSmall response body:\n"
  curl -isk ${CURLOPTS} ${BASE}/ | ${FILTER}

  printf "\n\nEmpty response:\n"
  curl -isk ${CURLOPTS} ${BASE}/empty | ${FILTER}

  printf "\n\nEcho body:\n"
  curl -isk ${CURLOPTS} -XPOST ${BASE}/echo -d'b548f7fa-a786-4858-82cb-c3f42759c7a9' | ${FILTER}

  printf "\n\nGet header:\n"
  curl -isk ${CURLOPTS} -H'X-Foo:Bar' ${BASE}/header | ${FILTER}

  printf "\n\nRequest large body:\n"
  dd if=/dev/urandom of=test.dat bs=25165824 count=1 2> /dev/null
  curl -sk ${CURLOPTS} -H'Expect:' --data-binary @test.dat -o r1.dat ${BASE}/large 2>&1 | ${FILTER}
  diff r1.dat test.dat

  printf "\n\nChunked response:\n"
  curl -isk ${CURLOPTS} ${BASE}/chunked  2>&1 | ${FILTER}

  if [ -z "${HTTP2}" ]; then
    printf "\n\nChunked response close:\n"
    curl -isk ${CURLOPTS} -H'Connection: close' ${BASE}/chunked ${BASE}/chunked 2>&1 | ${FILTER}
  fi

  if [ -z "${HTTP2}" ]; then
    printf "\n\nChunked request:\n"
    dd if=/dev/urandom of=test.dat bs=262144 count=1 2> /dev/null
    curl -sk -H'Expect:' -H'Transfer-Encoding: chunked' -XPOST --data-binary @test.dat \
      -o r1.dat ${BASE}/large \
      -o r2.dat ${BASE}/large

    diff r1.dat test.dat
    diff r2.dat test.dat
  fi
}

SERVER="./server1 ${SOPTS}"
if [ -n "${VALGRIND}" ]; then
  SERVER="valgrind --leak-check=full --log-file=valgrind.log ${SERVER}"
fi

echo "Command: ${SERVER}"
${SERVER} &
SPID="$!"

echo "HTTP Server pid: $!"

run 2>&1 | tee ${LOG}.log
kill -2 ${SPID}

diff --strip-trailing-cr ${LOG}.log ${LOG}-success.log
wait ${SPID}

if [ -n "${VALGRIND}" ]; then
  cat ./valgrind.log | cut -d = -f 5 | grep ERROR > valgrind-results.log 
  cat ./valgrind.log | cut -d = -f 5 | grep 'All heap blocks were freed' >> valgrind-results.log 
  diff valgrind-results.log valgrind-success.log
fi  

printf "\nDone!\n"




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
#set -x

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
LOG="server2"
if [ -n "${HTTP2}" ]; then
  LOG="server2-h2"
  if [ "${PROTO}" = "https" ]; then
    CURLOPTS="--http2"
  else
    CURLOPTS="--http2-prior-knowledge"
  fi
fi

SERVER="./server2 ${SOPTS}"

run() {
  sleep 1

  BASE="${PROTO}://localhost:${PORT}"
  FILTER='sed -E /(date|user-agent|trying|tcp|sessionid|etag|boundary|--)|^\*/Id'

  printf "\n\nGet empty:\n"
  curl -isk ${CURLOPTS} ${BASE}/get/empty | ${FILTER}

  printf "\n\nGet transport:\n"
  curl -isk ${CURLOPTS} ${BASE}/transport | ${FILTER}

  printf "\n\nGet not-found:\n"
  curl -isk ${CURLOPTS} ${BASE}/get/not_found | ${FILTER}

  printf "\n\nGet query:\n"
  curl -isk ${CURLOPTS} "${BASE}/get/query?foo=bar&baz=a%40z" | ${FILTER}
  
  printf "\n\nGet fail:\n"
  curl -isk ${CURLOPTS} "${BASE}/fail" 2>&1 | ${FILTER} 

  printf "\n\nPost urlencoded:\n"
  curl -isk ${CURLOPTS} -d'foo=bar&baz=a%40z' ${BASE}/post/urlencoded | ${FILTER}

  printf "\n\nPost urlencoded (raw body preserved):\n"
  curl -isk ${CURLOPTS} --data-raw '@books/[age = 31]' ${BASE}/post/urlencoded_raw | ${FILTER}

  printf "\n\nPut data:\n"
  curl -isk ${CURLOPTS} -XPUT -H'Content-Type:text/plain' -d'ff5fd857-c90b-4066-910f-a9a5d1fa1b47' ${BASE}/post/putdata | ${FILTER}

  base64 /dev/urandom | head -c 15165824 > ./test.dat

  if [ -z "${HTTP2}" ]; then
    printf "\n\nPost chunked:\n"
    curl -sk ${CURLOPTS} -XPOST -H'Expect:' -H'Transfer-Encoding: chunked' --data-urlencode bigparam@test.dat -o r1.dat \
      ${BASE}/post/bigparam 

    if ! cmp -s ./test.dat ./r1.dat; then
      echo "./test.dat and ./r1.dat differs"
    fi
  fi
  
  printf "\n\nPost multipart:\n"
  curl -sk ${CURLOPTS} -XPOST -H'Expect:' -F 'foo=bar' -F 'baz=a%40z' -F 'bigparam=@test.dat;type=text/plain' \
    ${BASE}/post/multipart | ${FILTER}

  printf "\n\nPost multipart without boundary:\n"
  curl -isk ${CURLOPTS} -XPOST -H'Content-Type: multipart/form-data' -d'x' ${BASE}/post/multipart | ${FILTER}

  printf "\n\nUnsupported HTTP method:\n"
  curl -isk ${CURLOPTS} -X TRACE ${BASE}/get/empty | ${FILTER}

  printf "\n\nPost malformed multipart body:\n"
  curl -isk ${CURLOPTS} -XPOST -H'Content-Type: multipart/form-data; boundary=zzz' \
    -d'not-a-multipart-body' ${BASE}/post/multipart | ${FILTER}

  printf "\n\nSession put:\n"
  curl -isk ${CURLOPTS} -c ./cookie.jar ${BASE}/session/put | ${FILTER}

  printf "\n\nSession get:\n"
  curl -isk ${CURLOPTS} -b ./cookie.jar ${BASE}/session/get | ${FILTER}

  printf "\n\nDirectory serve:\n"
  mkdir -p foo/bar
  echo '{"msg":"Hello"}' > foo/bar/hello.json
  curl -isk ${CURLOPTS} ${BASE}/dir/bar/hello.json | ${FILTER}

  printf "\n\nFile get:\n"
  curl -sk ${CURLOPTS} ${BASE}/file/test.dat -o r1.dat | ${FILTER}
  if ! cmp -s ./test.dat ./r1.dat; then
    echo "./test.dat and ./r1.dat differs"
  fi

  printf "\n\nFile2 get:\n"
  curl -sk ${CURLOPTS} ${BASE}/file2/test.dat -o r1.dat | ${FILTER}
  if ! cmp -s ./test.dat ./r1.dat; then
    echo "./test.dat and ./r1.dat differs"
  fi

  printf "\n\nFile get HEAD:\n"
  curl -sk ${CURLOPTS} -I ${BASE}/file/test.dat | ${FILTER}

  echo -n "ae0150d3-c811-4313-b5d5-89fcfc29f8c6" > chunks.txt

  printf "\n\nRange1:\n"
  curl -isk ${CURLOPTS} -H'Range: bytes=0-7' ${BASE}/file/chunks.txt | ${FILTER}

  printf "\n\nRange2:\n"
  curl -isk ${CURLOPTS} -H'Range: bytes=0-0' ${BASE}/file/chunks.txt | ${FILTER}

  printf "\n\nRange3:\n"
  curl -isk ${CURLOPTS} -H'Range: bytes=-1' ${BASE}/file/chunks.txt | ${FILTER}

  printf "\n\nRange4:\n"
  curl -isk ${CURLOPTS} -H'Range: bytes=-1111' ${BASE}/file/chunks.txt | ${FILTER}

  printf "\n\nRange5:\n"
  curl -isk ${CURLOPTS} -H'Range: bytes=' ${BASE}/file/chunks.txt | ${FILTER}

  printf "\n\nRange6:\n"
  curl -isk ${CURLOPTS} -H'Range: bytes=1' ${BASE}/file/chunks.txt | ${FILTER}

  printf "\n\nRange7:\n"
  curl -isk ${CURLOPTS} -H'Range: bytes=0-7,-1' ${BASE}/file/chunks.txt | ${FILTER}

}

if [ -n "${VALGRIND}" ]; then
  SERVER="valgrind --leak-check=full --log-file=valgrind2.log ${SERVER}"
fi

echo "Command: ${SERVER}"
${SERVER} &
SPID="$!"

echo "HTTP Server pid: $!"

run 2>&1 | tee ${LOG}.log
kill -2 ${SPID}
wait ${SPID}

diff --strip-trailing-cr ${LOG}.log ${LOG}-success.log

if [ -n "${VALGRIND}" ]; then
  cat ./valgrind2.log | cut -d = -f 5 | grep ERROR > valgrind2-results.log 
  cat ./valgrind2.log | cut -d = -f 5 | grep 'All heap blocks were freed' >> valgrind2-results.log 
  diff valgrind2-results.log valgrind2-success.log
fi  

printf "\nDone!\n"




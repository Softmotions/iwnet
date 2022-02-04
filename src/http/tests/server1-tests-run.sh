#!/usr/bin/env sh

set -e

SOPTS=""
PORT=9292
PROTO="http"

while [ $# -gt 0 ]; do
  case $1 in
    --valgrind)
      VALGRIND=1
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

run() {

  sleep 1

  BASE="${PROTO}://localhost:${PORT}"
  FILTER='sed -r /(date|user-agent|trying|tcp)|^\*/Id'

  printf "\n\nSmall response body:\n"
  curl -isk ${BASE}/ | ${FILTER}

  printf "\n\nEmpty response:\n"
  curl -isk ${BASE}/empty | ${FILTER}

  printf "\n\nEcho body:\n"
  curl -isk -XPOST ${BASE}/echo -d'b548f7fa-a786-4858-82cb-c3f42759c7a9' | ${FILTER}

  printf "\n\nGet header:\n"
  curl -isk -H'X-Foo:Bar' ${BASE}/header | ${FILTER}

  printf "\n\nRequest large body:\n"
  dd if=/dev/urandom of=test.dat bs=25165824 count=1 2> /dev/null
  curl -sk -H'Expect:' --data-binary @test.dat -o r1.dat ${BASE}/large 2>&1 | ${FILTER}
  diff r1.dat test.dat

  printf "\n\nChunked response:\n"
  curl -isk ${BASE}/chunked  2>&1 | ${FILTER}

  printf "\n\nChunked response close:\n"
  curl -isk -H'Connection: close' ${BASE}/chunked ${BASE}/chunked 2>&1 | ${FILTER}

  printf "\n\nChunked request:\n"
  dd if=/dev/urandom of=test.dat bs=262144 count=1 2> /dev/null
  curl -sk -H'Expect:' -H'Transfer-Encoding: chunked' -XPOST --data-binary @test.dat \
    -o r1.dat ${BASE}/large \
    -o r2.dat ${BASE}/large

  diff r1.dat test.dat
  diff r2.dat test.dat
}

SERVER="./server1 ${SOPTS}"
if [ -n "${VALGRIND}" ]; then
  SERVER="valgrind --leak-check=full --log-file=valgrind.log ${SERVER}"
fi

echo "Command: ${SERVER}"
${SERVER} &
SPID="$!"

echo "HTTP Server pid: $!"

run 2>&1 | tee server1.log
kill -2 ${SPID}

diff --strip-trailing-cr server1.log server1-success.log
wait ${SPID}

if [ -n "${VALGRIND}" ]; then
  cat ./valgrind.log | cut -d = -f 5 | grep ERROR > valgrind-results.log 
  cat ./valgrind.log | cut -d = -f 5 | grep 'All heap blocks were freed' >> valgrind-results.log 
  diff valgrind-results.log valgrind-success.log
fi  

printf "\nDone!\n"




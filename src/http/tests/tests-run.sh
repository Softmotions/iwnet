#!/usr/bin/env sh

set -e
SOPTS=""

while [ $# -gt 0 ]; do
  case $1 in
    --valgrind)
      VALGRIND=1
      shift
      ;;
    --)      
      shift
      SOPTS=$@
      break
      ;;
    *)
      shift
      ;;
  esac
done


PROTO="http"
if echo "${SOPTS}" | grep '\-\-ssl'; then
  PROTO="https"
fi

run() {

  sleep 1

  PORT=9292
  BASE="${PROTO}://localhost:${PORT}"
  FILTER='sed -r /(date|user-agent|trying|tcp)|^\*/Id'

  echo "\n\nSmall response body:"
  curl -isk ${BASE}/ | ${FILTER}

  echo "\n\nEmpty response:"
  curl -isk ${BASE}/empty | ${FILTER}

  echo "\n\nEcho body:"
  curl -isk -XPOST ${BASE}/echo -d'b548f7fa-a786-4858-82cb-c3f42759c7a9' | ${FILTER}

  echo "\n\nGet header:"
  curl -isk ${BASE}/host | ${FILTER}

  echo "\n\nRequest large body:"
  dd if=/dev/urandom of=test.dat bs=25165824 count=1 2> /dev/null
  curl -sk -H'Expect:' --data-binary @test.dat -o r1.dat ${BASE}/large 2>&1 | ${FILTER}
  diff r1.dat test.dat

  echo "\n\nChunked response:"
  curl -isk ${BASE}/chunked  2>&1 | ${FILTER}

  echo "\n\nChunked response close:"
  curl -isk -H'Connection: close' ${BASE}/chunked ${BASE}/chunked 2>&1 | ${FILTER}

  echo "\n\nChunked request:"
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

echo "Done!"




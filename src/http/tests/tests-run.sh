#!/usr/bin/env sh

set -e

run() {

  sleep 1

  PORT=9292
  BASE="http://localhost:${PORT}"
  FILTER='sed -r /(date|user-agent|trying|tcp)|^\*/Id'

  echo "\n\nSmall response body:"
  curl -is ${BASE}/ | ${FILTER}

  echo "\n\nEmpty response:"
  curl -is ${BASE}/empty | ${FILTER}

  echo "\n\nEcho body:"
  curl -XPOST -is ${BASE}/echo -d'b548f7fa-a786-4858-82cb-c3f42759c7a9' | ${FILTER}

  echo "\n\nGet header:"
  curl -is ${BASE}/host | ${FILTER}

  echo "\n\nRequest large body:"
  dd if=/dev/urandom of=test.dat bs=25165824 count=1 2> /dev/null
  curl -s -H'Expect:' --data-binary @test.dat -o r1.dat ${BASE}/large 2>&1 | ${FILTER}
  diff r1.dat test.dat

  echo "\n\nChunked response:"
  curl -is ${BASE}/chunked  2>&1 | ${FILTER}

  echo "\n\nChunked response close:"
  curl -H'Connection: close' -is ${BASE}/chunked ${BASE}/chunked 2>&1 | ${FILTER}

  echo "\n\nChunked request:"
  dd if=/dev/urandom of=test.dat bs=262144 count=1 2> /dev/null
  curl -s -H'Expect:' -H'Transfer-Encoding: chunked' -XPOST --data-binary @test.dat \
    -o r1.dat ${BASE}/large \
    -o r2.dat ${BASE}/large

  diff r1.dat test.dat
  diff r2.dat test.dat
}

valgrind --leak-check=full --log-file=valgrind.log ./server1 &
#./server1 &
SPID="$!"
echo "HTTP Server pid: $!"

run 2>&1 | tee server1.log
kill -2 ${SPID}

diff server1.log server1-success.log
wait ${SPID}

cat ./valgrind.log | cut -d = -f 5 | grep ERROR > valgrind-results.log 
cat ./valgrind.log | cut -d = -f 5 | grep 'All heap blocks were freed' >> valgrind-results.log 
diff valgrind-results.log valgrind-success.log

echo "Done!"




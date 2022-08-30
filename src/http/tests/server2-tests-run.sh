#!/usr/bin/env sh

set -e
#set -x

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

SERVER="./server2 ${SOPTS}"

run() {
  sleep 1

  BASE="${PROTO}://localhost:${PORT}"
  FILTER='sed -r /(date|user-agent|trying|tcp|sessionid|etag|boundary|--)|^\*/Id'

  printf "\n\nGet empty:\n"
  curl -isk ${BASE}/get/empty | ${FILTER}

  printf "\n\nGet not-found:\n"
  curl -isk ${BASE}/get/not_found | ${FILTER}

  printf "\n\nGet query:\n"
  curl -isk "${BASE}/get/query?foo=bar&baz=a%40z" | ${FILTER}
  
  printf "\n\nGet fail:\n"
  curl -isk "${BASE}/fail" 2>&1 | ${FILTER} 

  printf "\n\nPost urlencoded:\n"
  curl -isk -d'foo=bar&baz=a%40z' ${BASE}/post/urlencoded | ${FILTER}

  printf "\n\nPut data:\n"
  curl -isk -XPUT -H'Content-Type:text/plain' -d'ff5fd857-c90b-4066-910f-a9a5d1fa1b47' ${BASE}/post/putdata | ${FILTER}

  base64 /dev/urandom | head -c 15165824 > ./test.dat

  printf "\n\nPost chunked:\n"
  curl -sk -XPOST -H'Expect:' -H'Transfer-Encoding: chunked' --data-urlencode bigparam@test.dat -o r1.dat \
    ${BASE}/post/bigparam 

  if ! cmp -s ./test.dat ./r1.dat; then
    echo "./test.dat and ./r1.dat differs"
  fi
  
  printf "\n\nPost multipart:\n"
  curl -sk -XPOST -H'Expect:' -F 'foo=bar' -F 'baz=a%40z' -F 'bigparam=@test.dat;type=text/plain' \
    ${BASE}/post/multipart | ${FILTER}

  printf "\n\nSession put:\n"
  curl -isk -c ./cookie.jar ${BASE}/session/put | ${FILTER}

  printf "\n\nSession get:\n"
  curl -isk -b ./cookie.jar ${BASE}/session/get | ${FILTER}

  printf "\n\nDirectory serve:\n"
  mkdir -p foo/bar
  echo '{"msg":"Hello"}' > foo/bar/hello.json
  curl -isk ${BASE}/dir/bar/hello.json | ${FILTER}

  printf "\n\nFile get:\n"
  curl -sk ${BASE}/file/test.dat -o r1.dat | ${FILTER}
  if ! cmp -s ./test.dat ./r1.dat; then
    echo "./test.dat and ./r1.dat differs"
  fi

  printf "\n\nFile2 get:\n"
  curl -sk ${BASE}/file2/test.dat -o r1.dat | ${FILTER}
  if ! cmp -s ./test.dat ./r1.dat; then
    echo "./test.dat and ./r1.dat differs"
  fi

  printf "\n\nFile get HEAD:\n"
  curl -sk -I ${BASE}/file/test.dat | ${FILTER}

  echo -n "ae0150d3-c811-4313-b5d5-89fcfc29f8c6" > chunks.txt

  printf "\n\nRange1:\n"
  curl -isk -H'Range: bytes=0-7' ${BASE}/file/chunks.txt | ${FILTER}

  printf "\n\nRange2:\n"
  curl -isk -H'Range: bytes=0-0' ${BASE}/file/chunks.txt | ${FILTER}

  printf "\n\nRange3:\n"
  curl -isk -H'Range: bytes=-1' ${BASE}/file/chunks.txt | ${FILTER}

  printf "\n\nRange4:\n"
  curl -isk -H'Range: bytes=-1111' ${BASE}/file/chunks.txt | ${FILTER}

  printf "\n\nRange5:\n"
  curl -isk -H'Range: bytes=' ${BASE}/file/chunks.txt | ${FILTER}

  printf "\n\nRange6:\n"
  curl -isk -H'Range: bytes=1' ${BASE}/file/chunks.txt | ${FILTER}

  printf "\n\nRange7:\n"
  curl -isk -H'Range: bytes=0-7,-1' ${BASE}/file/chunks.txt | ${FILTER}

}

if [ -n "${VALGRIND}" ]; then
  SERVER="valgrind --leak-check=full --log-file=valgrind2.log ${SERVER}"
fi

echo "Command: ${SERVER}"
${SERVER} &
SPID="$!"

echo "HTTP Server pid: $!"

run 2>&1 | tee server2.log
kill -2 ${SPID}
wait ${SPID}

diff --strip-trailing-cr server2.log server2-success.log

if [ -n "${VALGRIND}" ]; then
  cat ./valgrind2.log | cut -d = -f 5 | grep ERROR > valgrind2-results.log 
  cat ./valgrind2.log | cut -d = -f 5 | grep 'All heap blocks were freed' >> valgrind2-results.log 
  diff valgrind2-results.log valgrind2-success.log
fi  

printf "\nDone!\n"




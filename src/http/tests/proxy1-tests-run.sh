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

SERVER="./proxy1 ${SOPTS}"

run() {
  sleep 1
  
  ARGS="-H Host:endpoint"
  BASE="${PROTO}://localhost:${PORT}"
  FILTER='sed -r /(date|user-agent|trying|tcp|sessionid|etag|boundary|--)|^\*/Id'

  printf "\n\nEcho:\n"
  curl -isk ${ARGS} ${BASE}/echo | ${FILTER}

  printf "\n\nGet empty:\n"
  curl -isk ${ARGS}  ${BASE}/get/empty | ${FILTER}

  printf "\n\nGet not-found:\n"
  curl -isk ${ARGS} ${BASE}/get/not_found | ${FILTER}

  printf "\n\nGet query:\n"
  curl -isk ${ARGS} "${BASE}/get/query?foo=bar&baz=a%40z" | ${FILTER}

  printf "\n\nGet fail:\n"
  curl -isk ${ARGS} "${BASE}/fail" 2>&1 | ${FILTER} 

  printf "\n\nPost urlencoded:\n"
  curl -isk ${ARGS} -d'foo=bar&baz=a%40z' ${BASE}/post/urlencoded | ${FILTER}

  printf "\n\nPut data:\n"
  curl -isk ${ARGS} -XPUT -H'Content-Type:text/plain' -d'ff5fd857-c90b-4066-910f-a9a5d1fa1b47' ${BASE}/post/putdata | ${FILTER}

  base64 /dev/urandom | head -c 15165824 > ./test.dat

  printf "\n\nPost chunked:\n"
  curl -sk ${ARGS} -XPOST -H'Expect:' -H'Transfer-Encoding: chunked' --data-urlencode bigparam@test.dat -o r1.dat \
    ${BASE}/post/bigparam 

  if ! cmp -s ./test.dat ./r1.dat; then
    echo "./test.dat and ./r1.dat differs"
  fi

  printf "\n\nPost multipart:\n"
  curl -sk ${ARGS} -XPOST -H'Expect:' -F 'foo=bar' -F 'baz=a%40z' -F 'bigparam=@test.dat;type=text/plain' \
    ${BASE}/post/multipart | ${FILTER}

  printf "\n\nSession put:\n"
  curl -isk ${ARGS} -c ./cookie.jar ${BASE}/session/put | ${FILTER}

  printf "\n\nSession get:\n"
  curl -isk ${ARGS} -b ./cookie.jar ${BASE}/session/get | ${FILTER}

  printf "\n\nDirectory serve:\n"
  mkdir -p foo/bar
  echo '{"msg":"Hello"}' > foo/bar/hello.json
  curl -isk ${ARGS} ${BASE}/dir/bar/hello.json | ${FILTER}
 
  printf "\n\nFile get:\n"
  curl -sk ${ARGS} ${BASE}/file/test.dat -o r1.dat | ${FILTER}
  if ! cmp -s ./test.dat ./r1.dat; then
    echo "./test.dat and ./r1.dat differs"
  fi

  printf "\n\nFile2 get:\n"
  curl -sk ${ARGS} ${BASE}/file2/test.dat -o r1.dat | ${FILTER}
  if ! cmp -s ./test.dat ./r1.dat; then
    echo "./test.dat and ./r1.dat differs"
  fi

  printf "\n\nFile get HEAD:\n"
  curl -sk ${ARGS} -I ${BASE}/file/test.dat | ${FILTER}
}

if [ -n "${VALGRIND}" ]; then
  SERVER="valgrind --leak-check=full --log-file=valgrind3.log ${SERVER}"
fi

echo "Command: ${SERVER}"
${SERVER} &
SPID="$!"

echo "HTTP Server pid: $!"

run 2>&1 | tee proxy1.log
kill -2 ${SPID}
wait ${SPID}

diff --strip-trailing-cr proxy1.log proxy1-success.log
printf "\nDone!\n"


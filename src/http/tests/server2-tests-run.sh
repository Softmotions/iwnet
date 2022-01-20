#!/usr/bin/env sh

# curl -v http://localhost:9292/get/empty 
#< HTTP/1.1 200 OK
#< connection: keep-alive
#< content-type: text/plain
#< content-length: 2
#OK

# curl -v http://localhost:9292/get/not_found
# Mark bundle as not supporting multiuse
#< HTTP/1.1 404 Not Found
#< Date: Thu, 20 Jan 2022 14:23:54 GMT
#< connection: keep-alive
#< content-type: text/plain
#< content-length: 19
#Not found from root

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

#curl -v 'http://localhost:9292/get/query?foo=bar&baz=a%40z'
#> GET /get/query?foo=bar&baz=a%40z HTTP/1.1
#> Host: localhost:9292
#> Accept: */*
#> 
#< HTTP/1.1 200 OK
#< connection: keep-alive
#< content-type: text/plain;
#< content-length: 15
#< 
#foo=bar&baz=a@z

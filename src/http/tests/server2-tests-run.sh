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

#curl -v 'http://localhost:9292/fail'
#> GET /fail HTTP/1.1
#* Empty reply from server
#curl: (52) Empty reply from server


#curl -v -d'foo=bar&baz=a%40z' 'http://localhost:9292/post/urlencoded'
#> POST /post/urlencoded HTTP/1.1
#> Host: localhost:9292
#> Accept: */*
#> Content-Length: 17
#> Content-Type: application/x-www-form-urlencoded
#> 
#< HTTP/1.1 200 OK
#< connection: keep-alive
#< content-type: text/plain;
#< content-length: 15
#< 
#* Connection #0 to host localhost left intact
#foo=bar&baz=a@za

# base64 /dev/urandom | head -c 25165824 > ./test.dat

#curl -v -XPUT -H'Content-Type:text/plain' -d'ff5fd857-c90b-4066-910f-a9a5d1fa1b47' 'http://localhost:9292/post/putdata'
#> PUT /post/putdata HTTP/1.1
#> Host: localhost:9292
#> Accept: */*
#> Content-Type:text/plain
#> Content-Length: 36
#> 
#< connection: keep-alive
#< content-type: text/plan
#< content-length: 36
#< 
#ff5fd857-c90b-4066-910f-a9a5d1fa1b47

# curl -s -XPOST -H'Expect:' -H'Transfer-Encoding: chunked' --data-urlencode bigparam@test.dat
# 'http://localhost:9292/post/bigparam' -o r1.dat
# diff ./test.dat ./r1.dat 

# Multipart
# curl -s -XPOST -H'Expect:' -F 'foo=bar' -F 'bigparam=@test.dat;type=text/html'  'http://localhost:9292/post/bigparam' -o r1.dat





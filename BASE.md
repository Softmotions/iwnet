# IWNET

Pure `C` asynchronous HTTP framework with support of websockets client/server, TLS 1.2 (SSL), routing.

Works on Linux, macOS, FreeBSD

* [Fast asynchronous HTTP server](./src/http) ([iwn_http_server.h](./src/http/iwn_http_server.h))
* [Web framework based on HTTP server](./src/http) ([iwn_wf.h](./src/http/iwn_wf.h))   
* Websocket client and server ([iwn_ws_server.h](./src/ws/iwn_ws_server.h), [iwn_ws_client.h](./src/ws/iwn_ws_client.h))
* Poller reactor ([iwn_poller.h](./src/poller/iwn_poller.h))
* SSL Layer is based on BearSSL ([iwn_brssl_poller_adapter.h](./src/ssl/iwn_brssl_poller_adapter.h))
* Manager of child processes ([iwn_proc.h](./src/poller/iwn_proc.h))
* Timer ([iwn_scheduler.h](./src/poller/iwn_scheduler.h))

## Build from sources

**Prerequisites**

* Linux, macOS or FreeBSD
* CMake 3.12 or greater
* gcc or clang compiler 
* GNU Make or Ninja 

**Building**

```sh
git clone https://github.com/Softmotions/iwnet.git

mkdir -p ./iwnet/build && cd ./iwnet/build

cmake .. -DCMAKE_BUILD_TYPE=RelWithDebInfo -DBUILD_EXAMPLES=ON

make 
```

## IWSTART

IWSTART is an automatic CMake initial project generator for C projects based on iowow / [iwnet](https://github.com/Softmotions/iwnet) / [ejdb2](https://github.com/Softmotions/ejdb) libs.

https://github.com/Softmotions/iwstart

# Used by

* [EJDB2 Embeddable JSON Database engine](https://github.com/Softmotions/ejdb)
* [Wirow Video Conferencing Platform](https://github.com/wirow-io/wirow-server)


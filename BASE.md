# IWNET

Pure `C` asynchronous HTTP framework with support of websockets client/server, TLS 1.2 (SSL), routing.

Works on Linux, macOS, FreeBSD

* [Fast asynchronous HTTP server](./src/http) ([iwn_http_server.h](./src/http/iwn_http_server.h))
* [Web framework based on HTTP server](./src/http) ([iwn_wf.h](./src/http/iwn_wf.h))   
* Websocket server ([iwn_ws_server.h](./src/ws/iwn_ws_server.h))
* Websocket client ([iwn_ws_client.h](./src/ws/iwn_ws_client.h))
* Poller reactor ([iwn_poller.h](./src/poller/iwn_poller.h))
* SSL Layer is based on BearSSL ([iwn_brssl_poller_adapter.h](./src/ssl/iwn_brssl_poller_adapter.h))
* Child process manager ([iwn_proc.h](./src/poller/iwn_proc.h))
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

# Used by

* [EJDB2 Embeddable JSON Database engine](https://ejdb.org)
* [Wirow Video Conferencing Platform](https://wirow.io)



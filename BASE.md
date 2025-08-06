# IWNET

Pure `C` asynchronous HTTP framework providing websockets client/server, SSL, reverse proxy and routing.

Works on Linux, macOS, FreeBSD

* [Fast asynchronous HTTP server](./src/http) ([iwn_http_server.h](./src/http/iwn_http_server.h))
* [Web framework based on HTTP server](./src/http) ([iwn_wf.h](./src/http/iwn_wf.h))   
* Ultra fast HTTP Reverse Proxy ([iwn_http_server.h](./src/http/iwn_http_server.h))
* Websocket client and server ([iwn_ws_server.h](./src/ws/iwn_ws_server.h), [iwn_ws_client.h](./src/ws/iwn_ws_client.h))
* Poller reactor ([iwn_poller.h](./src/poller/iwn_poller.h))
* SSL Layer is based on BearSSL ([iwn_brssl_poller_adapter.h](./src/ssl/iwn_brssl_poller_adapter.h))
* Manager of child processes ([iwn_proc.h](./src/poller/iwn_proc.h))
* Timer ([iwn_scheduler.h](./src/poller/iwn_scheduler.h))

# Build from sources

**Prerequisites**

* Linux, macOS or FreeBSD
* gcc or clang compiler (clang is preferred since allows code blocks API provided by this project)
* pkgconf or pkg-config

## Build by [Autark](https://github.com/Softmotions/autark)

```sh
./build.sh
```

**Installation**

```sh
./build.sh --prefix=$HOME/.local
```

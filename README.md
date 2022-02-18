# IWNET

Pure `C` asynchronous HTTP framework with support of websockets client/server, TLS 1.2 (SSL), routing.

Works on Linux, macOS, FreeBSD

* Fast asynchronous HTTP server (http_server.h)
* Web framework based on HTTP server (wf.h)   
* Websocket server (ws_server.h)
* Websocket client (ws_client.h)
* Poller reactor (poller.h)
* SSL poller fd adapter based on BearSSL (brssl_poller_adapter.h)
* Child process manager (proc.h)
* Timer (scheduler.h)

# IWNET

Pure `C` asynchronous HTTP framework with support of websockets client/server, TLS 1.2 (SSL), routing.

Works on Linux, macOS, FreeBSD

* Fast asynchronous HTTP server (iwn_http_server.h)
* Web framework based on HTTP server (iwn_wf.h)   
* Websocket server (iwn_ws_server.h)
* Websocket client (iwn_ws_client.h)
* Poller reactor (poller.h)
* SSL poller fd adapter based on BearSSL (iwn_brssl_poller_adapter.h)
* Child process manager (proc.h)
* Timer (iwn_scheduler.h)

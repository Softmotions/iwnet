# Asynchronous HTTP Framework

## Examples
### Simple echo server

```sh
  ./echo_http_server --ssl
 
  curl -k -XPUT -d'Hello' https://localhost:8080/echo
  Hello
  I'm an echo web server
```

echo_http_server.c

```c
#include "iwn_wf.h"

#include <iowow/iwconv.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <errno.h>

static struct iwn_poller *poller;
static struct iwn_wf_ctx *ctx;

static void _on_signal(int signo) {
  fprintf(stderr, "\nExiting...\n");
  iwn_poller_shutdown_request(poller);
}

static int _handle_echo(struct iwn_wf_req *req, void *user_data) {
  fprintf(stderr, "Echo handler called\n");
  iwn_http_response_printf(req->http, 200, "text/plain", "%.*s\n%s\n",
                           (int) req->body_len, req->body, (char*) user_data);
  return IWN_WF_RES_PROCESSED;
}

int main(int argc, char *argv[]) {
  signal(SIGPIPE, SIG_IGN);
  if (  signal(SIGTERM, _on_signal) == SIG_ERR
     || signal(SIGINT, _on_signal) == SIG_ERR) {
    return EXIT_FAILURE;
  }

  iwrc rc = 0;
  bool ssl = false;
  int port = 8080;

  for (int i = 1; i < argc; ++i) {
    if (strcmp(argv[i], "--ssl") == 0) {
      ssl = true;
    } else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
      port = iwatoi(argv[i + 1]);
    }
  }
  RCC(rc, finish, iw_init());              // Init iowow runtime, logging, etc..
  RCC(rc, finish, iwn_wf_create(0, &ctx)); // Create web server context
  RCC(rc, finish, iwn_wf_route(&(struct iwn_wf_route) {
    .ctx = ctx,
    .pattern = "/echo",
    .handler = _handle_echo,
    .user_data = "I'm an echo web server",
    .flags = IWN_WF_PUT | IWN_WF_POST
  }, 0));

  RCC(rc, finish, iwn_poller_create(0, 0, &poller));

  struct iwn_wf_server_spec spec = {
    .listen = "localhost",
    .port   = port,
    .poller = poller,
  };
  if (ssl) {
    spec.ssl.private_key = "./server-eckey.pem";
    spec.ssl.private_key_len = -1;
    spec.ssl.certs = "./server-ecdsacert.pem";
    spec.ssl.certs_len = -1;
  }

  // Print out a routes configuration.
  iwn_wf_route_print(ctx->root, stderr);
  // Configure HTTP server.
  RCC(rc, finish, iwn_wf_server(&spec, ctx));
  fprintf(stderr,
          "\nOpen terminal and run:\n\tcurl -k -XPUT -d'Hello' %s://%s:%d\n",
          (ssl ? "https" : "http"),
          spec.listen,
          spec.port);

  // Start fds poller reactor.
  iwn_poller_poll(poller);

finish:
  iwn_poller_destroy(&poller);
  if (rc) {
    iwlog_ecode_error3(rc);
    return EXIT_FAILURE;
  } else {
    return EXIT_SUCCESS;
  }
}
```

### Todo list REST API server

[todolist_http_server.c](https://github.com/Softmotions/iwnet/tree/master/src/http/examples/todolist_http_server.c)

```sh
./todolist_http_server --ssl
0001 [root:*] 
0002   [/todo> ALL
0003     {create:/([a-zA-z]+[a-z0-9A-Z]*)] PUT
0004     {get:/([0-9]+)] GET
0005     {remove:/([0-9]+)] DELETE
0006     [list:*] GET
0007     [done:*] POST

 Create a new 'Hello' todo entry:
	curl -k -XPUT -d'Say Hello' https://localhost:8080/todo/Hello
	curl -k -XPUT -d'Say Hello' https://localhost:8080/todo/Hello?done=1

 List all todo list items:
	curl -k https://localhost:8080/todo

 Get task #1 details:
	curl -k https://localhost:8080/todo/1

 Remove task #2 from todo list:
	curl -k -XDELETE https://localhost:8080/todo/2

 Update done status of task #2:
	curl -k -XPOST -d'id=2&done=1' https://localhost:8080/todo
```

### More examples 

You may find many helpful code examples by looking into 
[framework test code](https://github.com/Softmotions/iwnet/tree/master/src/http/tests)

* [server2.c](https://github.com/Softmotions/iwnet/tree/master/src/http/tests/server2.c)
* [server1.c](https://github.com/Softmotions/iwnet/tree/master/src/http/tests/server1.c)
* [HTTP Proxy: proxy1.c](https://github.com/Softmotions/iwnet/tree/master/src/http/tests/proxy1.c)

## HTTP/2

The HTTP server can transparently serve HTTP/1.1 and HTTP/2 clients on the same
listening socket. HTTP/2 is negotiated by TLS ALPN (`h2`) or, on plain text
connections, by the HTTP/2 connection preface (prior knowledge). The HTTP/1.1
`Upgrade: h2c` mechanism (RFC 9113 §3.2) is not supported.

HTTP/2 support is optional and requires the library to be built with
`IWN_ENABLE_HTTP2=1` (it depends on [libhive](https://github.com/Softmotions/libhive)).
The server opts in with `iwn_http_server_spec::http2` (`iwn_wf_server_spec::http2`
for the web framework). Requests are delivered to the very same request handler
and the `iwn_http_req` API (as well as the `iwn_wf` web framework) works
unchanged. Use `iwn_http_request_is_http2()` to detect the transport if needed.

```sh
  # Build with HTTP/2 support
  IWN_ENABLE_HTTP2=1 ./build.sh -c

  # Plain text HTTP/2 (prior knowledge)
  curl --http2-prior-knowledge http://localhost:8080/

  # HTTP/2 over TLS (ALPN)
  curl --http2 -k https://localhost:8443/
```

### HTTP/2 transport limitations

The HTTP/2 transport is a server side transport. Some HTTP/1.1 specific features
have no HTTP/2 counterpart:

* **Thread safety.** Of the response API only the *data* writes and the stream
  control calls are thread safe: `iwn_http_response_chunk_write()`,
  `iwn_http_response_stream_write()`, `iwn_http_response_chunk_end()`,
  `iwn_http_response_stream_end()` and `iwn_http_request_abort()` may be called
  from any thread; such calls are queued on the connection and applied by the
  connection thread. Response status/header setters and
  `iwn_http_response_stream_start()` must be called from the request handler
  thread.
* **Timeouts.** `iwn_http_server_spec::request_timeout_sec` is a whole-connection
  inactivity timeout. A quiet but healthy long-lived streaming request is
  terminated by it as well, since there is no per-stream idle timeout. Servers
  which serve such requests should disable the timeout (`request_timeout_sec = -1`)
  or keep it above the longest expected period of a completely idle stream.
* **Keep-alive.** An HTTP/2 connection is shared by concurrent streams and lives
  as long as both peers need it, so `iwn_http_connection_set_keep_alive()` and
  `iwn_http_connection_set_automatic()` have no effect on HTTP/2 requests.
* **Websocket.** Websocket over HTTP/2 (RFC 8441 extended `CONNECT`) is not
  implemented. `iwn_http_connection_set_upgrade()` and
  `iwn_http_inject_poller_events_handler()` are no-ops for HTTP/2 requests, so a
  websocket server must stay on HTTP/1.1.
* **Reverse proxy.** The `iwn_http_proxy_*` API is not available for requests
  served by the HTTP/2 transport, `iwn_http_proxy_url_set()` and friends return
  `false`.

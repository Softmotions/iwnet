/// Sample `todo list` HTTP REST API server

#include "iwn_wf.h"

#include <iowow/iwconv.h>
#include <iowow/iwxstr.h>

#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <errno.h>

static struct iwn_poller *poller;
static struct iwn_wf_ctx *ctx;

struct item {
  int   id;
  char *title;
  char *body;
  bool  done;
  struct item *next;
};

static struct item *items;

static void _on_signal(int signo) {
  fprintf(stderr, "\nExiting...\n");
  iwn_poller_shutdown_request(poller);
}

static void _item_destroy(struct item *item) {
  if (item) {
    free(item->title);
    free(item->body);
    free(item);
  }
}

static int _item_add(struct item *a) {
  int id = 0;
  if (items) {
    for (struct item *n = items; n; n = n->next) {
      if (n->id > id) {
        id = n->id;
      }
      if (n->next == 0) {
        a->id = id;
        n->next = a;
        break;
      }
    }
  } else {
    items = a;
  }
  return ++a->id;
}

/// Todo list create item.
///
/// * curl -XPUT -d'Say Hello' http://localhost:8080/todo/Hello
/// * curl -XPUT -d'Say Hello' http://localhost:8080/todo/Hello?done=1
///
static int _todo_create(struct iwn_wf_req *req, void *user_data) {
  iwrc rc = 0;
  int ret = IWN_WF_RES_INTERNAL_ERROR; // 500 code by default
  struct item *item;
  struct iwn_wf_route_submatch *m = iwn_wf_request_submatch_first(req);
  RCB(finish, item = calloc(1, sizeof(*item)));

  RCB(finish, item->title = malloc(m->ep - m->sp + 1));
  memcpy(item->title, m->sp, m->ep - m->sp);
  item->title[m->ep - m->sp] = '\0';

  if (req->body_len) {
    RCB(finish, item->body = strndup(req->body, req->body_len));
  } else {
    RCB(finish, item->body = strdup(""));
  }

  // Get done flag from query parameter:
  struct iwn_val val = iwn_pair_find_val(&req->query_params, "done", IW_LLEN("done"));
  if (val.len && strcmp(val.buf, "1") == 0) {
    item->done = true;
  }
  _item_add(item);

  // Write response to the client
  if (iwn_http_response_printf(req->http, 200, "text/plain", "%d\n", item->id)) {
    ret = IWN_WF_RES_PROCESSED;
  }

finish:
  if (rc) {
    iwlog_ecode_error3(rc);
    _item_destroy(item);
  }
  return ret;
}

/// List all todo list items.
///
/// * curl http://localhost:8080/todo
///
static int _todo_list(struct iwn_wf_req *req, void *user_data) {
  iwrc rc = 0;
  int ret = IWN_WF_RES_INTERNAL_ERROR;
  IWXSTR *xstr;

  // For the sake of simplicity response is not streamed and assembled as buffer.
  RCB(finish, xstr = iwxstr_new());

  for (struct item *n = items; n; n = n->next) {
    iwxstr_printf(xstr, "%03d %s\t%s\n", n->id, n->title, n->body);
  }

  if (iwn_http_response_write(req->http, 200, "text/plain", iwxstr_ptr(xstr), iwxstr_size(xstr))) {
    ret = IWN_WF_RES_PROCESSED;
  }

finish:
  iwxstr_destroy(xstr);
  if (rc) {
    iwlog_ecode_error3(rc);
  }
  return 0;
}

static int _todo_get(struct iwn_wf_req *req, void *user_data) {
  return 0;
}

static int _todo_remove(struct iwn_wf_req *req, void *user_data) {
  return 0;
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

  // Configure routes
  struct iwn_wf_route *parent;

  RCC(rc, finish, iwn_wf_route(&(struct iwn_wf_route) {
    .ctx = ctx,
    .pattern = "/todo",
    .flags = IWN_WF_METHODS_ALL // Matched all HTTP methods
  }, &parent));

  // Creates a new todo item
  RCC(rc, finish, iwn_wf_route(&(struct iwn_wf_route) {
    .parent = parent,
    .pattern = "^/([a-zA-z]+[a-z0-9A-Z]*)",
    .flags = IWN_WF_PUT,
    // If pattern starts with `^` it will be processed as regexp.
    .handler = _todo_create,
    .tag = "create"
  }, 0));

  // Gets todo item by id
  RCC(rc, finish, iwn_wf_route(&(struct iwn_wf_route) {
    .parent = parent,
    .pattern = "^/([0-9]+)",
    .handler = _todo_get,
    .tag = "get"
  }, 0));

  // Removes todo item by id
  RCC(rc, finish, iwn_wf_route(&(struct iwn_wf_route) {
    .parent = parent,
    .pattern = "^/([0-9]+)",
    .handler = _todo_remove,
    .flags = IWN_WF_DELETE,
    .tag = "remove"
  }, 0));

  // List all todo items
  RCC(rc, finish, iwn_wf_route(&(struct iwn_wf_route) {
    .parent = parent,
    .handler = _todo_list,
    .tag = "list"
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
  // Start fds poller reactor.
  iwn_poller_poll(poller);

finish:
  iwn_poller_destroy(&poller);
  for (struct item *t = items, *n = 0; t; t = n) {
    n = t->next, _item_destroy(t);
  }
  if (rc) {
    iwlog_ecode_error3(rc);
    return EXIT_FAILURE;
  } else {
    return EXIT_SUCCESS;
  }
}

#pragma once
#include "poller.h"

typedef intptr_t iwn_http_server_handle_t;

iwrc iwn_http_server_create(
  struct iwn_poller *p, int port, const char *listen, bool http,
  iwn_http_server_handle_t *out_handle);

iwrc iwn_http_server_dispose(iwn_http_server_handle_t h);

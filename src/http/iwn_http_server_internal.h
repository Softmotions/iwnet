#pragma once

#include "iwn_http_server.h"

void iwn_http_request_wf_set(
  struct iwn_http_req*, void *user_data,
  void (*wf_on_request_dispose)(struct iwn_http_req*),
  void (*wf_on_response_headers_write)(struct iwn_http_req*));

void* iwn_http_request_wf_data(struct iwn_http_req*);

void iwn_http_request_ws_set(struct iwn_http_req*, void *user_data);

void* iwn_http_request_ws_data(struct iwn_http_req*);

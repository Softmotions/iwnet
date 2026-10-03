#include "grpc_tests.h"

/// Concurrent unary requests on a single client connection.

static atomic_int _closed_requests;

static void _req_on_message7(struct iwn_grpc_req_message *msg, bool *cont) {
  iw_stepbox_on(&sbox[0], STEP_REQ_ON_MESSAGE, 1);

  char buf[255];
  iwbin2hex(buf, sizeof(buf), (void*) msg->msg.buf, msg->msg.len);
  IWN_ASSERT(strcmp(
               "0a2e31623336626565342d653564342d343035372d613964352d6130613334336161333663613a20416e746f6e2023311001",
               buf) == 0);
}

static void _req_on_closed7(const struct iwn_grpc_req_ctx *rctx) {
  iw_stepbox_on(&sbox[0], STEP_REQ_ON_CLOSED, 1);
  // Close the client only after both concurrent requests have completed.
  if (atomic_fetch_add(&_closed_requests, 1) == 1) {
    bool ret = iwn_grpc_client_close(rctx->client_ctx.client);
    IWN_ASSERT(ret);
  }
}

static iwrc _run_tests(void) {
  iwrc rc = 0;
  iw_stepbox_reset(&sbox[0], _sbox_lsnr);
  atomic_store(&_closed_requests, 0);

  struct iwn_grpc_req_spec spec = {
    .client = _ctx.client,
    .path = "/helloworld.Greeter/SayHello",
    .on_error = _req_on_error,
    .on_message = _req_on_message7,
    .on_outgoing_messages_queue_drained = _req_on_outgoing_messages_queue_drained,
    .on_closed = _req_on_closed7,
    .on_destroy = _req_on_destroy,
  };

  struct iwn_val val;
  _iwn_val_init(&val, "0a05416e746f6e");

  struct _req_test_ctx *rctx1 = _req_test_ctx_create();
  struct _req_test_ctx *rctx2 = _req_test_ctx_create();
  IWN_ASSERT_FATAL(rctx1);
  IWN_ASSERT_FATAL(rctx2);

  spec.user_data = rctx1;
  IWN_ASSERT_FATAL(iwn_grpc_client_request_open(&spec, &val, 0, &rctx1->req_id) == 0);

  spec.user_data = rctx2;
  IWN_ASSERT_FATAL(iwn_grpc_client_request_open(&spec, &val, 0, &rctx2->req_id) == 0);

  _iwn_val_destroy(&val);
  return rc;
}

int main(int argc, char *argv[]) {
  _parse_port(argc, argv);
  _signals_setup();

  char url[128];
  _grpc_url(url, sizeof(url));

  iwrc rc = iwn_grpc_init();
  RCRET(rc);

  struct iwpool *pool = iwpool_create_empty();
  RCB(finish, pool);
  _ctx.pool = pool;

  struct iwn_grpc_client_spec spec = {
    .url = url,
    .on_handshake = _on_handshake,
    .on_closed = _on_closed,
    .on_error = _on_error,
    .on_destroy = _on_destroy,
  };

  RCC(rc, finish, iwn_poller_create(3, 1, &_ctx.poller));
  spec.poller = _ctx.poller;
  RCC(rc, finish, iwn_grpc_client_open(&spec, &_ctx.client));

  pthread_t poll_thread = 0;
  RCC(rc, finish, iwn_poller_poll_in_thread(_ctx.poller, "poller", &poll_thread));
  IWN_ASSERT((rc = _run_tests()) == 0);
  if (rc) {
    iwn_poller_shutdown_request(_ctx.poller);
  }
  pthread_join(poll_thread, 0);

finish:
  IWN_ASSERT(sbox[0].steps[STEP_ON_DESTROY] == 1);
  IWN_ASSERT(sbox[0].steps[STEP_ON_CLOSED] == 1);
  IWN_ASSERT(sbox[0].steps[STEP_ON_HANDSHAKE] == 1);
  IWN_ASSERT(sbox[0].steps[STEP_REQ_ON_MESSAGE] == 2);
  IWN_ASSERT(sbox[0].steps[STEP_REQ_ON_DRAINED] == 2);
  IWN_ASSERT(sbox[0].steps[STEP_REQ_ON_CLOSED] == 2);
  IWN_ASSERT(sbox[0].steps[STEP_REQ_ON_ERROR] == 0);
  if (rc) {
    iwlog_ecode_error3(rc);
  }
  IWN_ASSERT(rc == 0);
  _ctx_destroy();
  return iwn_assertions_failed > 0 ? 1 : 0;
}

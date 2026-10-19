#include "grpc_tests.h"

/// gRPC error status propagation: server returns grpc-status=3 / grpc-message="bad argument"; client must report GRPC_ERROR_INVALID_ARGUMENT and the message.
///

static void _req_on_error5(struct iwn_grpc_req_ctx *ctx) {
  iw_stepbox_on(&sbox[0], STEP_REQ_ON_ERROR, 1);
  IW_TEST_ASSERT(ctx->rc == GRPC_ERROR_INVALID_ARGUMENT);
  IW_TEST_ASSERT(ctx->error_explained);
  IW_TEST_ASSERT(strcmp(ctx->error_explained, "bad argument") == 0);
}

static void _req_on_message5(struct iwn_grpc_req_message *msg, bool *cont) {
  iw_stepbox_on(&sbox[0], STEP_REQ_ON_MESSAGE, 1);
}

static iwrc _run_tests(void) {
  iwrc rc = 0;
  iw_stepbox_reset(&sbox[0], _sbox_lsnr);

  // grpc_mock.py sends HTTP2 200 response headers followed by trailers
  // grpc-status=3 and grpc-message="bad argument".
  struct iwn_grpc_req_spec spec = {
    .client = _ctx.client,
    .path = "/error.Greeter/SayHello",
    .on_error = _req_on_error5,
    .on_message = _req_on_message5,
    .on_outgoing_messages_queue_drained = _req_on_outgoing_messages_queue_drained,
    .on_closed = _req_on_closed,
    .on_destroy = _req_on_destroy,
  };

  struct iwn_val val;
  _iwn_val_init(&val, "0a05416e746f6e");

  struct _req_test_ctx *rctx = _req_test_ctx_create();
  IW_TEST_ASSERT_FATAL(rctx);
  spec.user_data = rctx;

  RCC(rc, finish, iwn_grpc_client_request_open(&spec, &val, 0, &rctx->req_id));

finish:
  _iwn_val_destroy(&val);
  if (rc) {
    iwlog_ecode_error3(rc);
    _req_on_destroy_impl(rctx);
  }
  return rc;
}

static void test_error_status(void) {
  pthread_t poll_thread = 0;
  iwrc rc = _grpc_test_setup(&poll_thread);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  IW_TEST_ASSERT_EQUAL(rc = _run_tests(), 0);
  if (rc) {
    iwn_poller_shutdown_request(_ctx.poller);
  }
  pthread_join(poll_thread, 0);

  IW_TEST_ASSERT(sbox[0].steps[STEP_ON_DESTROY] == 1);
  IW_TEST_ASSERT(sbox[0].steps[STEP_ON_CLOSED] == 1);
  IW_TEST_ASSERT(sbox[0].steps[STEP_ON_HANDSHAKE] == 1);
  IW_TEST_ASSERT(sbox[0].steps[STEP_REQ_ON_MESSAGE] == 0);
  IW_TEST_ASSERT(sbox[0].steps[STEP_REQ_ON_DRAINED] == 1);
  IW_TEST_ASSERT(sbox[0].steps[STEP_REQ_ON_CLOSED] == 1);
  IW_TEST_ASSERT(sbox[0].steps[STEP_REQ_ON_ERROR] == 1);
  IW_TEST_ASSERT(sbox[0].steps[STEP_ON_ERROR] == 0);
  if (rc) {
    iwlog_ecode_error3(rc);
  }
  IW_TEST_ASSERT(rc == 0);
  _grpc_test_teardown();
}

int main(int argc, char *argv[]) {
  static const struct iw_test_case cases[] = {
    IW_TEST_CASE(test_error_status),
  };
  return iw_test_run(argc, argv, IW_TEST_SUITE("grpc_error_status", cases, 0, 0));
}

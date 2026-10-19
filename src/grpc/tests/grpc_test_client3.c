#include "grpc_tests.h"

static void _req_on_message1(struct iwn_grpc_req_message *msg, bool *cont) {
  int steps = iw_stepbox_on(&sbox[0], STEP_REQ_ON_MESSAGE, 1);
  struct _req_test_ctx *tctx = msg->ctx.spec.user_data;
  if (tctx->rc || tctx->stop_streaming) {
    return;
  }
  if (steps >= 3) {
    tctx->stop_streaming = true;
  }

  // Now repeat the messages
  struct iwn_val val;
  struct iwn_grpc_req_ctx *rctx = &msg->ctx;
  _iwn_val_init(&val, "0a05416e746f6e");

  iwrc rc = iwn_grpc_client_stream_next_message(rctx, &val, tctx->stop_streaming);
  IW_TEST_ASSERT(rc == 0);
  if (rc) {
    iwlog_ecode_error3(rc);
  }
  _iwn_val_destroy(&val);
}

static iwrc _run_tests(void) {
  iwrc rc = 0;
  iw_stepbox_reset(&sbox[0], _sbox_lsnr);

  struct iwn_grpc_req_spec spec = {
    .client = _ctx.client,
    .path = "/helloworld.Greeter/SayHelloBidiStream",
    .on_error = _req_on_error,
    .on_message = _req_on_message1,
    .on_outgoing_messages_queue_drained = _req_on_outgoing_messages_queue_drained,
    .on_closed = _req_on_closed,
    .on_destroy = _req_on_destroy,
    .client_streaming = true,
  };

  struct iwn_val val;
  // name:"Anton"
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

static void test_bidi_streaming(void) {
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
  IW_TEST_ASSERT(sbox[0].steps[STEP_REQ_ON_CLOSED] == 1);
  IW_TEST_ASSERT(sbox[0].steps[STEP_REQ_ON_MESSAGE] == 4);
  IW_TEST_ASSERT(sbox[0].steps[STEP_REQ_ON_DRAINED] == 4);
  IW_TEST_ASSERT(sbox[0].steps[STEP_ON_HANDSHAKE] == 1);
  if (rc) {
    iwlog_ecode_error3(rc);
  }
  IW_TEST_ASSERT(rc == 0);
  _grpc_test_teardown();
}

int main(int argc, char *argv[]) {
  static const struct iw_test_case cases[] = {
    IW_TEST_CASE(test_bidi_streaming),
  };
  return iw_test_run(argc, argv, IW_TEST_SUITE("grpc_bidi_streaming", cases, 0, 0));
}

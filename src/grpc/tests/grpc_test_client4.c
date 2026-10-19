#include "grpc_tests.h"

/// Low-level gRPC frame parsing: first message split across two HTTP/2 DATA frames, remaining messages packed into one DATA frame. Uses grpc_mock.py.
///
static void _req_on_message4(struct iwn_grpc_req_message *msg, bool *cont) {
  int n = iw_stepbox_on(&sbox[0], STEP_REQ_ON_MESSAGE, 1);
  IW_TEST_ASSERT(n >= 1 && n <= 3);

  static const char *expected[] = {
    "0a0141", // message: "A"
    "0a0142", // message: "B"
    "0a0143", // message: "C"
  };

  char buf[64];
  iwbin2hex(buf, sizeof(buf), (void*) msg->msg.buf, msg->msg.len);
  IW_TEST_ASSERT(strcmp(expected[n - 1], buf) == 0);
}

static iwrc _run_tests(void) {
  iwrc rc = 0;
  iw_stepbox_reset(&sbox[0], _sbox_lsnr);

  // Low-level framing test against grpc_mock.py in server-streaming mode:
  // the first gRPC message is split across two DATA frames and the remaining
  // two messages are packed into a single DATA frame.
  struct iwn_grpc_req_spec spec = {
    .client = _ctx.client,
    .path = "/framing.Greeter/SayHelloStreamReply",
    .on_error = _req_on_error,
    .on_message = _req_on_message4,
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

static void test_stream_framing(void) {
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
  IW_TEST_ASSERT(sbox[0].steps[STEP_REQ_ON_MESSAGE] == 3);
  IW_TEST_ASSERT(sbox[0].steps[STEP_REQ_ON_DRAINED] == 1);
  IW_TEST_ASSERT(sbox[0].steps[STEP_REQ_ON_CLOSED] == 1);
  IW_TEST_ASSERT(sbox[0].steps[STEP_REQ_ON_ERROR] == 0);
  if (rc) {
    iwlog_ecode_error3(rc);
  }
  IW_TEST_ASSERT(rc == 0);
  _grpc_test_teardown();
}

int main(int argc, char *argv[]) {
  static const struct iw_test_case cases[] = {
    IW_TEST_CASE(test_stream_framing),
  };
  return iw_test_run(argc, argv, IW_TEST_SUITE("grpc_stream_framing", cases, 0, 0));
}

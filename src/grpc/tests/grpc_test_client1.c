#include "grpc_tests.h"

static void _req_on_message1(struct iwn_grpc_req_message *msg, bool *cont) {
  iw_stepbox_on(&sbox[0], STEP_REQ_ON_MESSAGE, 1);
  struct _req_test_ctx *tctx = msg->ctx.spec.user_data;
  IW_TEST_ASSERT_FATAL(iwn_vals_add_val(tctx->pool, &tctx->vals, &msg->msg, true));

  char buf[255];
  iwbin2hex(buf, sizeof(buf), (void*) msg->msg.buf, msg->msg.len);
  IW_TEST_ASSERT(strcmp(
               "0a2e31623336626565342d653564342d343035372d613964352d6130613334336161333663613a20416e746f6e2023311001",
               buf) == 0);
}

static iwrc _run_tests(void) {
  iwrc rc = 0;
  iw_stepbox_reset(&sbox[0], _sbox_lsnr);

  // grpcurl -plaintext -import-path . -proto ./helloworld.proto -d '{"name":"Anton"}'  localhost:50051
  // helloworld.Greeter/SayHello
  // Message: name:"Anton": 0a05416e746f6e

  struct iwn_grpc_req_spec spec = {
    .client = _ctx.client,
    .path = "/helloworld.Greeter/SayHello",
    .on_error = _req_on_error,
    .on_message = _req_on_message1,
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

static void test_unary(void) {
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
  IW_TEST_ASSERT(sbox[0].steps[STEP_REQ_ON_MESSAGE] == 1);
  IW_TEST_ASSERT(sbox[0].steps[STEP_REQ_ON_DRAINED] == 1);
  IW_TEST_ASSERT(sbox[0].steps[STEP_REQ_ON_CLOSED] == 1);
  if (rc) {
    iwlog_ecode_error3(rc);
  }
  IW_TEST_ASSERT(rc == 0);
  _grpc_test_teardown();
}

int main(int argc, char *argv[]) {
  static const struct iw_test_case cases[] = {
    IW_TEST_CASE(test_unary),
  };
  return iw_test_run(argc, argv, IW_TEST_SUITE("grpc_unary", cases, 0, 0));
}

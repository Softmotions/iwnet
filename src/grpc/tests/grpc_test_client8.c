#include "grpc_tests.h"

/// Per-request authorization header: the request sets its own `authorization` value
/// which overrides the (unset) client-wide authorization.
///
/// The mock server (`grpc_mock.py --expect-authorization`) responds with
/// `grpc-status 16` (UNAUTHENTICATED) unless the request carries the expected
/// `authorization` header, so the case fails if the header is not sent.
///

/// Value of the `authorization` header expected by the mock server.
#define TEST_AUTHORIZATION "Bearer per-request-token"

static void _req_on_message8(struct iwn_grpc_req_message *msg, bool *cont) {
  iw_stepbox_on(&sbox[0], STEP_REQ_ON_MESSAGE, 1);
  struct _req_test_ctx *tctx = msg->ctx.spec.user_data;
  IW_TEST_ASSERT_FATAL(iwn_vals_add_val(tctx->pool, &tctx->vals, &msg->msg, true));

  char buf[255];
  iwbin2hex(buf, sizeof(buf), (void*) msg->msg.buf, msg->msg.len);
  IW_TEST_ASSERT_STR_EQUAL(buf, "0a0141");
  // The request context exposes the request spec.
  IW_TEST_ASSERT_STR_EQUAL(msg->ctx.spec.authorization, TEST_AUTHORIZATION);
}

static iwrc _run_tests(void) {
  iwrc rc = 0;
  iw_stepbox_reset(&sbox[0], _sbox_lsnr);

  struct iwn_grpc_req_spec spec = {
    .client = _ctx.client,
    .path = "/helloworld.Greeter/SayHello",
    .authorization = TEST_AUTHORIZATION,
    .on_error = _req_on_error,
    .on_message = _req_on_message8,
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

static void test_request_authorization(void) {
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
  IW_TEST_ASSERT(sbox[0].steps[STEP_REQ_ON_ERROR] == 0);
  IW_TEST_ASSERT(sbox[0].steps[STEP_ON_ERROR] == 0);
  if (rc) {
    iwlog_ecode_error3(rc);
  }
  IW_TEST_ASSERT(rc == 0);
  _grpc_test_teardown();
}

int main(int argc, char *argv[]) {
  static const struct iw_test_case cases[] = {
    IW_TEST_CASE(test_request_authorization),
  };
  return iw_test_run(argc, argv, IW_TEST_SUITE("grpc_request_authorization", cases, 0, 0));
}

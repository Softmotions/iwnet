#include "grpc_tests.h"

/// Concurrent unary requests on a single client connection.

static atomic_int _closed_requests;

static void _req_on_message7(struct iwn_grpc_req_message *msg, bool *cont) {
  iw_stepbox_on(&sbox[0], STEP_REQ_ON_MESSAGE, 1);

  char buf[255];
  iwbin2hex(buf, sizeof(buf), (void*) msg->msg.buf, msg->msg.len);
  IW_TEST_ASSERT(strcmp(
               "0a2e31623336626565342d653564342d343035372d613964352d6130613334336161333663613a20416e746f6e2023311001",
               buf) == 0);
}

static void _req_on_closed7(const struct iwn_grpc_req_ctx *rctx) {
  iw_stepbox_on(&sbox[0], STEP_REQ_ON_CLOSED, 1);
  // Close the client only after both concurrent requests have completed.
  if (atomic_fetch_add(&_closed_requests, 1) == 1) {
    bool ret = iwn_grpc_client_close(rctx->client_ctx.client);
    IW_TEST_ASSERT(ret);
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
  IW_TEST_ASSERT_FATAL(rctx1);
  IW_TEST_ASSERT_FATAL(rctx2);

  spec.user_data = rctx1;
  IW_TEST_ASSERT_FATAL(iwn_grpc_client_request_open(&spec, &val, 0, &rctx1->req_id) == 0);

  spec.user_data = rctx2;
  IW_TEST_ASSERT_FATAL(iwn_grpc_client_request_open(&spec, &val, 0, &rctx2->req_id) == 0);

  _iwn_val_destroy(&val);
  return rc;
}

static void test_concurrent_unary(void) {
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
  IW_TEST_ASSERT(sbox[0].steps[STEP_REQ_ON_MESSAGE] == 2);
  IW_TEST_ASSERT(sbox[0].steps[STEP_REQ_ON_DRAINED] == 2);
  IW_TEST_ASSERT(sbox[0].steps[STEP_REQ_ON_CLOSED] == 2);
  IW_TEST_ASSERT(sbox[0].steps[STEP_REQ_ON_ERROR] == 0);
  if (rc) {
    iwlog_ecode_error3(rc);
  }
  IW_TEST_ASSERT(rc == 0);
  _grpc_test_teardown();
}

int main(int argc, char *argv[]) {
  static const struct iw_test_case cases[] = {
    IW_TEST_CASE(test_concurrent_unary),
  };
  return iw_test_run(argc, argv, IW_TEST_SUITE("grpc_concurrent_unary", cases, 0, 0));
}

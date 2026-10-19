#include "iwtests.h"
#include "iwn_utils.h"
#include "iwn_scheduler.h"
#include <iowow/iwlog.h>
#include <iowow/iwtp.h>
#include <inttypes.h>

static int64_t st, et;
static struct iwn_poller *poller;

static void _on_timeout(void *arg) {
  iwn_ts(&et);
  IW_TEST_ASSERT(et - st < 200);
  IW_TEST_ASSERT(et - st >= 150);
  iwn_poller_shutdown_request(poller);
}

static void test_scheduled_timeout(void) {
  iwrc rc = 0;

  RCC(rc, finish, iwn_poller_create(1, 1, &poller));
  RCC(rc, finish, iwn_ts(&st));
  RCC(rc, finish, iwn_schedule(&(struct iwn_scheduler_spec) {
    .task_fn = _on_timeout,
    .poller = poller,
    .timeout_ms = 155,
  }));

  iwn_poller_poll(poller);

finish:
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  IW_TEST_ASSERT_TRUE(et >= st);
}

static void suite_cleanup(void) {
  iwn_poller_destroy(&poller);
}

int main(int argc, char *argv[]) {
  static const struct iw_test_case cases[] = {
    IW_TEST_CASE(test_scheduled_timeout),
  };
  iwlog_init();
  return iw_test_run(argc, argv, IW_TEST_SUITE("poller_scheduler", cases, 0, suite_cleanup));
}

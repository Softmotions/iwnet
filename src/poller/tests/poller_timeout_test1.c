#include "iwtests.h"
#include "iwn_utils.h"
#include "iwn_poller.h"

#include <iowow/iwlog.h>
#include <iowow/iwp.h>

#include <unistd.h>
#include <errno.h>

static int fds[2] = { -1, -1 };
static struct iwn_poller *poller;

static void test_poll_timeout(void) {
  iwrc rc = 0;
  int64_t ts1 = 0, ts2 = 0;

  RCC(rc, finish, iwlog_init());
  RCC(rc, finish, iwn_poller_create(1, 1, &poller));

  RCN(finish, pipe(fds));
  RCC(rc, finish, iwn_poller_add(&(struct iwn_poller_task) {
    .poller = poller,
    .fd = fds[0],
    .events = IWN_POLLIN,
    .timeout = 2,
  }));

  RCC(rc, finish, iwn_ts(&ts1));
  iwn_poller_poll(poller);
  RCC(rc, finish, iwn_ts(&ts2));

  IW_TEST_ASSERT(ts2 - ts1 < 2100);
  IW_TEST_ASSERT(ts2 - ts1 >= 2000);

finish:
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
}

static void suite_cleanup(void) {
  if (fds[1] > -1) {
    close(fds[1]);
  }
  iwn_poller_destroy(&poller);
}

int main(int argc, char *argv[]) {
  static const struct iw_test_case cases[] = {
    IW_TEST_CASE(test_poll_timeout),
  };
  return iw_test_run(argc, argv, IW_TEST_SUITE("poller_timeout", cases, 0, suite_cleanup));
}

#include "utils/tests.h"
#include "utils/utils.h"
#include "scheduler.h"
#include <iowow/iwtp.h>
#include <inttypes.h>

static int cnt;
static int64_t st, et;
static struct poller *poller;
static IWTP tp;

static void _on_timeout(void *arg) {
  utils_ts(&et);
  IWN_ASSERT(et - st < 200 && et - st >= 150);
  poller_shutdown_request(poller);
}

int main(int argc, char *argv[]) {
  iwrc rc = 0;
  iwlog_init();
  RCC(rc, finish, iwtp_start("stest1-", 4, 0, &tp));
  RCC(rc, finish, poller_create(1, 1, &poller));
  RCC(rc, finish, utils_ts(&st));
  RCC(rc, finish, schedule(&(struct scheduler_spec) {
    .task_fn = _on_timeout,
    .poller = poller,
    .timeout_ms = 155,
    .thread_pool = tp
  }));

  poller_poll(poller);

finish:
  poller_destroy(&poller);
  iwtp_shutdown(&tp, true);
  IWN_ASSERT(rc == 0);
  IWN_ASSERT(et >= st);
  return asserts_failed > 0 ? 1 : 0;
}

#include "iwn_tests.h"
#include "iwn_utils.h"
#include "iwn_scheduler.h"
#include <iowow/iwtp.h>
#include <inttypes.h>

static int64_t st, et;
static struct iwn_poller *poller;

static void _on_timeout(void *arg) {
  iwn_ts(&et);
  IWN_ASSERT(et - st < 200 && et - st >= 150);
  iwn_poller_shutdown_request(poller);
}

int main(int argc, char *argv[]) {
  iwrc rc = 0;
  iwlog_init();
  RCC(rc, finish, iwn_poller_create(1, 1, &poller));
  RCC(rc, finish, iwn_ts(&st));
  RCC(rc, finish, iwn_schedule(&(struct iwn_scheduler_spec) {
    .task_fn = _on_timeout,
    .poller = poller,
    .timeout_ms = 155,
  }));

  iwn_poller_poll(poller);

finish:
  iwn_poller_destroy(&poller);
  IWN_ASSERT(rc == 0);
  IWN_ASSERT(et >= st);
  return iwn_assertions_failed > 0 ? 1 : 0;
}

#include "utils/tests.h"
#include "utils/utils.h"
#include "poller.h"

#include <iowow/iwp.h>

#include <unistd.h>
#include <errno.h>

int main(int argc, char *argv[]) {
  iwrc rc = 0;
  int fds[2] = { -1, -1 };
  struct iwn_poller *poller;

  RCC(rc, finish, iwlog_init());
  RCC(rc, finish, iwn_poller_create(1, 1, &poller));

  RCN(finish, pipe(fds));
  RCC(rc, finish, iwn_poller_add(&(struct iwn_poller_task) {
    .poller = poller,
    .fd = fds[0],
    .events = IWN_POLLIN,
    .timeout = 2,
  }));

  int64_t ts1 = 0, ts2 = 0;
  RCC(rc, finish, iwn_ts(&ts1));
  iwn_poller_poll(poller);
  RCC(rc, finish, iwn_ts(&ts2));

  IWN_ASSERT(ts2 - ts1 < 2100);
  IWN_ASSERT(ts2 - ts1 >= 2000);

finish:
  close(fds[1]);
  iwn_poller_destroy(&poller);
  IWN_ASSERT(rc == 0);
  return iwn_assertions_failed > 0 ? 1 : 0;
}

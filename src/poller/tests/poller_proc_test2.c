// Tests of the managed process group support (`iwn_proc_spec.kill_process_group`).
//
// A process started with `kill_process_group` becomes a leader of its own session and
// process group. The process module keeps it registered until the whole process group
// is empty, so:
//   - `iwn_proc_wait*()` completes only when the process tree is finished,
//   - `iwn_proc_wait_fast()` keeps the leader semantics,
//   - `iwn_proc_kill()`/`iwn_proc_kill_all()` signal the whole process tree.
//
// Every test starts `/bin/sh -c 'sleep 300 &'`: the shell exits immediately while the
// background `sleep` keeps the process group alive, so the leader exit is observable
// while the tree is still running. A `SIGKILL` to the group terminates the tree.
//
// The tests do not start the poller: no stdout/stderr callbacks are used, so no poller
// tasks are created.

#include "iwtests.h"
#include "iwn_proc.h"

#include <iowow/iwlog.h>

#include <signal.h>
#include <unistd.h>

static struct iwn_poller *poller;
static int exit_calls;

static int suite_init(void) {
  iwlog_init();
  return iwn_poller_create(1, 1, &poller) ? 1 : 0;
}

static void suite_cleanup(void) {
  iwn_proc_dispose2(SIGKILL, 3000);
  iwn_poller_destroy(&poller);
}

static void _on_exit(const struct iwn_proc_ctx *ctx) {
  ++exit_calls;
}

/// @return `true` if the process group `pgid` is still running.
static bool _pg_alive(pid_t pgid) {
  return kill(-pgid, 0) == 0;
}

/// Spawns `/bin/sh -c 'sleep 300 &'`: the shell exits at once, the background `sleep`
/// keeps the process group alive.
static iwrc _spawn_tree(pid_t *pid) {
  return iwn_proc_spawn(&(struct iwn_proc_spec) {
    .poller = poller,
    .path = "/bin/sh",
    .args = (const char*[]) { "-c", "sleep 300 &", 0 },
    .kill_process_group = true,
    .on_exit = _on_exit,
  }, pid);
}

static void test_poller_proc2_group_tree(void) {
  iwrc rc;
  pid_t pid = -1;
  bool timeout = false;

  exit_calls = 0;
  RCC(rc, finish, _spawn_tree(&pid));

  // The shell leader exits, but the background `sleep` keeps the group alive.
  RCC(rc, finish, iwn_proc_wait_timeout(pid, 1000, &timeout));
  IW_TEST_ASSERT_TRUE(timeout);
  IW_TEST_ASSERT_TRUE_FATAL(_pg_alive(pid));

  // The group kill terminates the whole process tree.
  iwn_proc_kill(pid, SIGKILL);
  RCC(rc, finish, iwn_proc_wait_timeout(pid, 5000, &timeout));
  IW_TEST_ASSERT_FALSE(timeout);
  IW_TEST_ASSERT_FALSE(_pg_alive(pid));
  IW_TEST_ASSERT_EQUAL(exit_calls, 1);
  IW_TEST_ASSERT_EQUAL(iwn_proc_num_managed(), 0);

finish:
  if (rc) {
    iwlog_ecode_error3(rc);
  }
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
}

static void test_poller_proc2_group_tree_wait_fast(void) {
  iwrc rc;
  pid_t pid = -1;
  bool timeout = false;

  RCC(rc, finish, _spawn_tree(&pid));

  // The leader is reaped, but the process tree is still registered and running.
  RCC(rc, finish, iwn_proc_wait_fast(pid));
  IW_TEST_ASSERT_TRUE_FATAL(_pg_alive(pid));
  IW_TEST_ASSERT_TRUE(iwn_proc_num_managed() > 0);

  // `iwn_proc_kill_all()` signals the whole tree.
  iwn_proc_kill_all(SIGKILL);
  RCC(rc, finish, iwn_proc_wait_timeout(pid, 5000, &timeout));
  IW_TEST_ASSERT_FALSE(timeout);
  IW_TEST_ASSERT_FALSE(_pg_alive(pid));
  IW_TEST_ASSERT_EQUAL(iwn_proc_num_managed(), 0);

finish:
  if (rc) {
    iwlog_ecode_error3(rc);
  }
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
}

static void test_poller_proc2_group_empty(void) {
  iwrc rc;
  pid_t pid = -1;
  bool timeout = true;

  // No descendants: the process group is finished together with its leader.
  RCC(rc, finish, iwn_proc_spawn(&(struct iwn_proc_spec) {
    .poller = poller,
    .path = "/bin/sh",
    .args = (const char*[]) { "-c", "exit 0", 0 },
    .kill_process_group = true,
  }, &pid));

  RCC(rc, finish, iwn_proc_wait_timeout(pid, 5000, &timeout));
  IW_TEST_ASSERT_FALSE(timeout);
  IW_TEST_ASSERT_EQUAL(iwn_proc_num_managed(), 0);

finish:
  if (rc) {
    iwlog_ecode_error3(rc);
  }
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
}

int main(int argc, char *argv[]) {
  static const struct iw_test_case cases[] = {
    IW_TEST_CASE(test_poller_proc2_group_tree),
    IW_TEST_CASE(test_poller_proc2_group_tree_wait_fast),
    IW_TEST_CASE(test_poller_proc2_group_empty),
  };
  return iw_test_run(argc, argv, IW_TEST_SUITE("poller_proc2", cases, suite_init, suite_cleanup));
}

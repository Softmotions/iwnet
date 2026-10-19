#include "iwtests.h"
#include "iwn_proc.h"

#include <iowow/iwlog.h>
#include <iowow/iwxstr.h>

#include <sys/wait.h>
#include <signal.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>

static struct iwn_poller *poller;
static pthread_t poller_thr;

static struct iwxstr *xstdout, *xstderr;
static int code;

static void* _poller_worker(void *arg) {
  IW_TEST_ASSERT_PTR_NOT_NULL(poller);
  if (!poller) {
    return 0;
  }
  iwn_poller_poll(poller);
  return 0;
}

static int suite_init(void) {
  iwlog_init();
  xstdout = iwxstr_create_empty();
  xstderr = iwxstr_create_empty();
  return (xstdout && xstderr) ? 0 : 1;
}

static void suite_cleanup(void) {
  iwn_proc_dispose2(SIGTERM, 0);
  iwxstr_destroy(xstderr);
  iwxstr_destroy(xstdout);
}

static void _on_echo_stdout(const struct iwn_proc_ctx *ctx, const char *buf, size_t len) {
  iwxstr_cat(xstdout, buf, len);
}

static void _on_echo_stderr(const struct iwn_proc_ctx *ctx, const char *buf, size_t len) {
  iwxstr_cat(xstderr, buf, len);
}

static void _on_echo1_exit(const struct iwn_proc_ctx *ctx) {
  code = WIFEXITED(ctx->wstatus) ? WEXITSTATUS(ctx->wstatus) : -1;
}

static void test_echo_stdout(void) {
  int pid;
  iwrc rc = 0;

  iwxstr_clear(xstdout);
  iwxstr_clear(xstderr);
  RCC(rc, finish, iwn_poller_create(1, 1, &poller));

  code = -1;

  RCC(rc, finish, iwn_proc_spawn(&(struct iwn_proc_spec) {
    .poller = poller,
    .path = "./echo",
    .on_stdout = _on_echo_stdout,
    .on_stderr = _on_echo_stderr,
    .on_exit = _on_echo1_exit,
    .write_stdin = true,
  }, &pid));

  pthread_create(&poller_thr, 0, _poller_worker, 0);
  RCC(rc, finish, iwn_proc_stdin_write(pid, "a6aa91b3-35ee-40f2-a94f-67f08a59de3e",
                                       sizeof("a6aa91b3-35ee-40f2-a94f-67f08a59de3e") - 1, true));
  iwn_proc_wait(pid);
  pthread_join(poller_thr, 0);

  IW_TEST_ASSERT_STR_EQUAL(iwxstr_ptr(xstdout), "a6aa91b3-35ee-40f2-a94f-67f08a59de3e");
  IW_TEST_ASSERT_EQUAL(code, 0);

finish:
  if (rc) {
    iwlog_ecode_error3(rc);
  }
  iwn_poller_destroy(&poller);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
}

static void test_echo_stderr(void) {
  int pid;
  iwrc rc = 0;

  iwxstr_clear(xstdout);
  iwxstr_clear(xstderr);
  RCC(rc, finish, iwn_poller_create(1, 1, &poller));

  code = -1;

  RCC(rc, finish, iwn_proc_spawn(&(struct iwn_proc_spec) {
    .poller = poller,
    .path = "./echo",
    .args = (const char*[]) { "-stderr", 0 },
    .on_stdout = _on_echo_stdout,
    .on_stderr = _on_echo_stderr,
    .on_exit = _on_echo1_exit,
    .write_stdin = true,
  }, &pid));

  pthread_create(&poller_thr, 0, _poller_worker, 0);
  RCC(rc, finish, iwn_proc_stdin_write(pid, "45f42994-fea8-4d41-9256-33720f42feb8",
                                       sizeof("45f42994-fea8-4d41-9256-33720f42feb8") - 1, true));

  iwn_proc_wait(pid);
  pthread_join(poller_thr, 0);

  IW_TEST_ASSERT_STR_EQUAL(iwxstr_ptr(xstderr), "45f42994-fea8-4d41-9256-33720f42feb8");
  IW_TEST_ASSERT_STR_EQUAL(iwxstr_ptr(xstdout), "");
  IW_TEST_ASSERT_EQUAL(iwxstr_size(xstdout), 0);
  IW_TEST_ASSERT_EQUAL(code, 0);

finish:
  if (rc) {
    iwlog_ecode_error3(rc);
  }
  iwn_poller_destroy(&poller);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
}

int main(int argc, char *argv[]) {
  static const struct iw_test_case cases[] = {
    IW_TEST_CASE(test_echo_stdout),
    IW_TEST_CASE(test_echo_stderr),
  };
  return iw_test_run(argc, argv, IW_TEST_SUITE("poller_proc", cases, suite_init, suite_cleanup));
}

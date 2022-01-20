#include "utils/tests.h"
#include "proc.h"

#include <iowow/iwxstr.h>

#include <wait.h>
#include <signal.h>
#include <pthread.h>
#include <string.h>

struct iwn_poller *poller;
pthread_t poller_thr;
pthread_barrier_t poller_br;

IWXSTR *xstdout, *xstderr;
int code;

static void* _poller_worker(void *arg) {
  IWN_ASSERT_FATAL(poller);
  pthread_barrier_wait(&poller_br);
  iwn_poller_poll(poller);
  return 0;
}

static iwrc init(void) {
  pthread_barrier_init(&poller_br, 0, 2);
  xstdout = iwxstr_new();
  xstderr = iwxstr_new();
  iwrc rc = iwn_poller_create(1, 1, &poller);
  RCRET(rc);
  pthread_create(&poller_thr, 0, _poller_worker, 0);
  pthread_barrier_wait(&poller_br);
  return rc;
}

static void shutdown(void) {
  iwn_proc_dispose();
  iwn_poller_shutdown_request(poller);
  if (poller_thr) {
    pthread_join(poller_thr, 0);
  }
  pthread_barrier_destroy(&poller_br);
  iwxstr_destroy(xstderr);
  iwxstr_destroy(xstdout);
  iwn_poller_destroy(&poller);
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

static iwrc test_echo1(void) {
  int pid;
  iwrc rc = 0;

  iwxstr_clear(xstdout);
  iwxstr_clear(xstderr);

  code = -1;

  RCC(rc, finish, iwn_proc_spawn(&(struct iwn_proc_spec) {
    .poller = poller,
    .path = "./echo",
    .on_stdout = _on_echo_stdout,
    .on_stderr = _on_echo_stderr,
    .on_exit = _on_echo1_exit,
    .write_stdin = true,
  }, &pid));

  RCC(rc, finish, iwn_proc_stdin_write(pid, "a6aa91b3-35ee-40f2-a94f-67f08a59de3e",
                                   sizeof("a6aa91b3-35ee-40f2-a94f-67f08a59de3e") - 1, true));
  iwn_proc_wait(pid);

  IWN_ASSERT(strcmp("a6aa91b3-35ee-40f2-a94f-67f08a59de3e", iwxstr_ptr(xstdout)) == 0);
  IWN_ASSERT(code == 0);

finish:
  if (rc) {
    iwlog_ecode_error3(rc);
  }
  return rc;
}

static iwrc test_echo2(void) {
  int pid;
  iwrc rc = 0;

  iwxstr_clear(xstdout);
  iwxstr_clear(xstderr);
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

  RCC(rc, finish, iwn_proc_stdin_write(pid, "45f42994-fea8-4d41-9256-33720f42feb8",
                                   sizeof("45f42994-fea8-4d41-9256-33720f42feb8") - 1, true));
  iwn_proc_wait(pid);

  IWN_ASSERT(strcmp("45f42994-fea8-4d41-9256-33720f42feb8", iwxstr_ptr(xstderr)) == 0);
  IWN_ASSERT(strcmp("", iwxstr_ptr(xstdout)) == 0);
  IWN_ASSERT(iwxstr_size(xstdout) == 0);
  IWN_ASSERT(code == 0);

finish:
  if (rc) {
    iwlog_ecode_error3(rc);
  }
  return rc;
}

int main(int argc, char *argv[]) {
  iwrc rc = 0;
  iwlog_init();
  RCC(rc, finish, init());
  RCC(rc, finish, test_echo1());
  RCC(rc, finish, test_echo2());


finish:
  shutdown();
  IWN_ASSERT(rc == 0);
  return iwn_assertions_failed > 0 ? 1 : 0;
}

#include "iwtests.h"
#include "iwn_poller.h"

#include <iowow/iwlog.h>

#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>

static int fds[2] = { -1, -1 };
static struct iwn_poller *poller;

static iwrc _make_non_blocking(int fd) {
  int rci, flags;
  while ((flags = fcntl(fd, F_GETFL, 0)) == -1 && errno == EINTR);
  if (flags == -1) {
    return iwrc_set_errno(IW_ERROR_ERRNO, errno);
  }
  while ((rci = fcntl(fd, F_SETFL, flags | O_NONBLOCK)) == -1 && errno == EINTR);
  if (rci == -1) {
    return iwrc_set_errno(IW_ERROR_ERRNO, errno);
  }
  return 0;
}

static int64_t _on_ready_write(const struct iwn_poller_task *t, uint32_t events) {
  write(t->fd, "test", sizeof("test"));
  return 0;
}

static int64_t _on_ready_read(const struct iwn_poller_task *t, uint32_t events) {
  char buf[sizeof("test")];
  int rci = read(t->fd, buf, sizeof(buf));
  IW_TEST_ASSERT_EQUAL(rci, (int) sizeof(buf));
  IW_TEST_ASSERT_EQUAL(strncmp(buf, "test", sizeof(buf)), 0);
  rci = read(t->fd, buf, sizeof(buf));
  IW_TEST_ASSERT_EQUAL(rci, -1);
  IW_TEST_ASSERT_EQUAL(errno, EAGAIN);
  iwn_poller_shutdown_request(poller);
  return 0;
}

static void test_pipe_et(void) {
  iwrc rc = 0;

  IW_TEST_ASSERT_EQUAL_FATAL(pipe(fds), 0);
  RCC(rc, finish, _make_non_blocking(fds[0]));
  RCC(rc, finish, _make_non_blocking(fds[1]));
  RCC(rc, finish, iwn_poller_create(2, 1, &poller));

  RCC(rc, finish, iwn_poller_add(&(struct iwn_poller_task) {
    .fd = fds[1],     // write
    .on_ready = _on_ready_write,
    .events_mod = IWN_POLLET,
    .poller = poller
  }));

  RCC(rc, finish, iwn_poller_add(&(struct iwn_poller_task) {
    .fd = fds[0],     // read
    .on_ready = _on_ready_read,
    .events = IWN_POLLIN,
    .events_mod = IWN_POLLET,
    .poller = poller
  }));

  RCC(rc, finish, iwn_poller_arm_events(poller, fds[1], IWN_POLLOUT));

  iwn_poller_poll(poller);

finish:
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
}

static void suite_cleanup(void) {
  iwn_poller_destroy(&poller);
  if (fds[0] > -1) {
    close(fds[0]);
  }
  if (fds[1] > -1) {
    close(fds[1]);
  }
}

int main(int argc, char *argv[]) {
  static const struct iw_test_case cases[] = {
    IW_TEST_CASE(test_pipe_et),
  };
  iwlog_init();
  return iw_test_run(argc, argv, IW_TEST_SUITE("poller_pipe", cases, 0, suite_cleanup));
}

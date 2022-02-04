#include "utils/tests.h"
#include "poller.h"

#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>

int fds[2];
struct iwn_poller *poller;

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
  IWN_ASSERT(rci == sizeof(buf));
  IWN_ASSERT(strncmp(buf, "test", sizeof(buf)) == 0);
  rci = read(t->fd, buf, sizeof(buf));
  IWN_ASSERT(rci == -1);
  IWN_ASSERT(errno == EAGAIN);
  iwn_poller_shutdown_request(poller);
  return 0;
}

int main(int argc, char *argv[]) {
  iwrc rc = 0;
  iwlog_init();

  int rci = pipe(fds);
  IWN_ASSERT_FATAL(rci == 0);

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
  iwn_poller_destroy(&poller);
  IWN_ASSERT(rc == 0);
  return iwn_assertions_failed > 0 ? 1 : 0;
}

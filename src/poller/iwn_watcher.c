#include "iwn_watcher.h"

#include <iowow/iwlog.h>
#include <iowow/iwrefs.h>

#include <stdlib.h>
#include <errno.h>
#include <unistd.h>

struct iwn_watcher {
  int fd;
  struct iwref_holder ref;
  struct iwn_poller  *poller;
  void  (*on_event)(const struct inotify_event *evt, void *on_event_user_data);
  void *on_event_user_data;
  bool  destroy;
};

static void _watcher_destroy(void *d) {
  struct iwn_watcher *w = d;
  if (w) {
    if (w->fd > -1) {
      if (w->poller) {
        iwn_poller_remove(w->poller, w->fd);
      } else {
        close(w->fd);
      }
      w->fd = -1;
    }
    free(w);
  }
}

static void _on_dispose(const struct iwn_poller_task *t) {
  struct iwn_watcher *w = t->user_data;
  w->fd = -1;
  w->poller = 0;
  iwref_unref(&w->ref);
}

static int64_t _on_ready(const struct iwn_poller_task *t, uint32_t events) {
  ssize_t len;
  struct iwn_watcher *w = t->user_data;
  char buf[4096] __attribute__((aligned(__alignof__(struct inotify_event))));
  for ( ; ; ) {
    len = read(t->fd, buf, sizeof(buf));
    if (len <= 0) {
      if (len == -1 && errno != EWOULDBLOCK && errno != EAGAIN) {
        return -1;
      }
      break;
    }
  }
  const struct inotify_event *event;
  for (char *ptr = buf; ptr < buf + len; ptr += sizeof(struct inotify_event) + event->len) {
    event = (const struct inotify_event*) ptr;
    w->on_event(event, w->on_event_user_data);
  }
  return 0;
}

iwrc iwn_watcher_create(const struct iwn_watcher_spec *spec, struct iwn_watcher **out) {
  iwrc rc = 0;
  if (!spec || !out || !spec->poller || !spec->on_event) {
    return IW_ERROR_INVALID_ARGS;
  }
  struct iwn_watcher *w = malloc(sizeof(*w));
  if (!w) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  iwref_init(&w->ref, w, _watcher_destroy);
  w->destroy = false;
  w->on_event = spec->on_event;
  w->on_event_user_data = spec->on_event_user_data;
  w->poller = spec->poller;
  w->fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
  if (w->fd == -1) {
    rc = iwrc_set_errno(IW_ERROR_ERRNO, errno);
    goto finish;
  }

  rc = iwn_poller_add(&(struct iwn_poller_task) {
    .poller = spec->poller,
    .fd = w->fd,
    .user_data = w,
    .events = IWN_POLLIN,
    .events_mod = IWN_POLLET,
    .on_ready = _on_ready,
    .on_dispose = _on_dispose
  });
  if (!rc) {
    iwref_ref(&w->ref);
  }

finish:
  if (rc) {
    iwref_unref(&w->ref);
  }
  return rc;
}

iwrc iwn_watcher_add(struct iwn_watcher *w, const char *path, uint32_t mask, int *out_wfd) {
  if (!w || !path) {
    return IW_ERROR_INVALID_ARGS;
  }
  if (out_wfd) {
    *out_wfd = 0;
  }
  if (!mask) {
    mask = IN_MODIFY | IN_CREATE | IN_DELETE;
  }
  int wfd = inotify_add_watch(w->fd, path, mask);
  if (wfd == -1) {
    return iwrc_set_errno(IW_ERROR_ERRNO, errno);
  }
  if (out_wfd) {
    *out_wfd = wfd;
  }
  return 0;
}

/// Remove resource from watch list.
iwrc iwn_watcher_remove(struct iwn_watcher *w, int wfd) {
  if (!w || wfd < 0) {
    return IW_ERROR_INVALID_ARGS;
  }
  if (inotify_rm_watch(w->fd, wfd) == -1) {
    return iwrc_set_errno(IW_ERROR_ERRNO, errno);
  }
  return 0;
}

void iwn_watcher_destroy(struct iwn_watcher *w) {
  if (w) {
    if (!__sync_bool_compare_and_swap(&w->destroy, false, true)) {
      if (w->fd > -1 && w->poller) {
        iwn_poller_remove(w->poller, w->fd);
      }
      iwref_unref(&w->ref);
    }
  }
}

#pragma once

 #include <sys/inotify.h>

/// Directory/file changes watcher based on inotify.

#include "iwn_poller.h"

IW_EXTERN_C_START;

struct iwn_watcher;

struct iwn_watcher_spec {
  struct iwn_poller *poller;
  void (*on_event)(const struct inotify_event *evt, void *on_event_user_data);
  void *on_event_user_data;
};

/// Create an watcher instance. Latery it should be closed by iwn_watcher_destroy().
IW_EXPORT iwrc iwn_watcher_create(const struct iwn_watcher_spec *spec, struct iwn_watcher **out);

/// Add the `path` resource to inotify watch list with given inotify mask.
/// If mask is zero then default mask will be used: IN_MODIFY | IN_CREATE | IN_DELETE
IW_EXPORT iwrc iwn_watcher_add(struct iwn_watcher*, const char *path, uint32_t mask, int *out_wfd);

/// Remove resource from watch list.
IW_EXPORT iwrc iwn_watcher_remove(struct iwn_watcher*, int wfd);

IW_EXPORT void iwn_watcher_destroy(struct iwn_watcher *w);

IW_EXTERN_C_END;

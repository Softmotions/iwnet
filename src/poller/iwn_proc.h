#pragma once

#include "iwn_poller.h"

IW_EXTERN_C_START

struct iwn_proc_ctx {
  /// Child pid.
  pid_t pid;

  /// Child process wait status: `man 2 wait`
  int wstatus;

  /// Arbitrary user data.
  void *user_data;
};

struct iwn_proc_spec {
  /// Poller associated with spec
  struct iwn_poller *poller;

  /// Path to executable.
  const char *path;

  /// Zero terminated array of arguments,
  /// args[0] is the name assocated with programm beeng executed.
  const char **args;

  /// Zero terminated array of environment vars of the form key=value.
  const char **env;

  /// Arbitrary user data.
  void *user_data;

  /// Stdout callback.
  void (*on_stdout)(const struct iwn_proc_ctx *ctx, const char *buf, size_t len);

  /// Strderr callback.
  void (*on_stderr)(const struct iwn_proc_ctx *ctx, const char *buf, size_t len);

  /// On child process exit.
  void (*on_exit)(const struct iwn_proc_ctx *ctx_exit);

  /// On fork handler. We are on the child side if pid is zero.
  void (*on_fork)(const struct iwn_proc_ctx *ctx, pid_t pid);

  /// It true set the ability to write into stdin of the child process
  bool write_stdin;
};

IW_EXPORT iwrc iwn_proc_spawn(const struct iwn_proc_spec *spec, int *out_pid);

IW_EXPORT iwrc iwn_proc_wait(pid_t pid);

IW_EXPORT iwrc iwn_proc_stdin_write(pid_t pid, const void *buf, size_t len, bool close);

IW_EXPORT iwrc iwn_proc_stdin_close(pid_t pid);

IW_EXPORT void iwn_proc_kill(pid_t pid, int signum);

IW_EXPORT void iwn_proc_kill_all(int signum);

IW_EXPORT iwrc iwn_proc_kill_ensure(struct iwn_poller *poller, pid_t pid, int signum, int max_attempts, int last_signum);

IW_EXPORT void iwn_proc_ref(pid_t pid);

IW_EXPORT void iwn_proc_unref(pid_t pid);

IW_EXPORT void iwn_proc_dispose(void);

IW_EXPORT IW_ALLOC char* iwn_proc_command_get(const struct iwn_proc_spec *spec);

IW_EXTERN_C_END

#pragma once

#include "iwn_poller.h"

IW_EXTERN_C_START

struct iwn_proc_ctx {

  /// Child pid.
  int pid;

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

  /// It true set the ability to write into stdin of the child process
  bool write_stdin;
};

IW_EXPORT iwrc iwn_proc_spawn(const struct iwn_proc_spec *spec, int *out_pid);

IW_EXPORT iwrc iwn_proc_wait(int pid);

IW_EXPORT iwrc iwn_proc_stdin_write(int pid, const void *buf, size_t len, bool close);

IW_EXPORT iwrc iwn_proc_stdin_close(int pid);

IW_EXPORT void iwn_proc_kill(int pid, int signum);

IW_EXPORT void iwn_proc_kill_all(int signum);

IW_EXPORT void iwn_proc_dispose(void);

IW_EXPORT IW_ALLOC char* iwn_proc_command_get(const struct iwn_proc_spec *spec);

IW_EXTERN_C_END

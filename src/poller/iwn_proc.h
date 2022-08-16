#pragma once

/// Process management library.

#include "iwn_poller.h"

IW_EXTERN_C_START

/// Process context available for process events callback.
struct iwn_proc_ctx {
  /// Child pid.
  pid_t pid;

  /// Child process wait status: `man 2 wait`
  int wstatus;

  /// Arbitrary user data.
  void *user_data;
};

/// Process launch specification.
struct iwn_proc_spec {
  /// Poller associated with spec
  struct iwn_poller *poller;

  /// Path to executable.
  const char *path;

  /// Zero terminated array of arguments,
  /// args[0] is the name associated with program being executed.
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

  /// If true use the PATH environment variable to locate exact path to the executable.
  bool find_executable_in_path;
};

/// Spawn (fork) new process according to the given specification.
/// @param spec Process specification.
/// @param[out] Process `pid` holder.
///
IW_EXPORT iwrc iwn_proc_spawn(const struct iwn_proc_spec *spec, pid_t *out_pid);

/// Blocks current thread until the child process identified by `pid` became inactive.
IW_EXPORT iwrc iwn_proc_wait(pid_t pid);

/// Blocks current thread until all child processes managed by this module became inactive.
IW_EXPORT void iwn_proc_wait_all(void);

/// Writes `buf` of size `len` into process standard input.
/// @param pid Process pid
/// @param buf Data buffer
/// @param len Data buffer length
/// @param close If `true` file descriptor of parent side will be closed after write.
///
IW_EXPORT iwrc iwn_proc_stdin_write(pid_t pid, const void *buf, size_t len, bool close);

/// Closes stdin write file descriptor on parent side.
IW_EXPORT iwrc iwn_proc_stdin_close(pid_t pid);

/// Sends `signum` signal to the child process identified by `pid`.
IW_EXPORT void iwn_proc_kill(pid_t pid, int signum);

/// Sends `signum` to all managed processes.
IW_EXPORT void iwn_proc_kill_all(int signum);

/// Sends a sequence of signals to the managed process identified by `pid`.
///
/// - If `max_attempts` > 0 `signum` will be sent to the process `max_attempts` times then `last_signum` will be send.
/// - If `max_attempts` < 0 `signum` will be send to the process and then after `max_attempts` seconds `last_signum`
///   will be send.
///
/// @param poller The poller used to schedule signal attempts actions via `iwn_scheduler.h` api.
///
IW_EXPORT iwrc iwn_proc_kill_ensure(
  struct iwn_poller *poller, pid_t pid, int signum, int max_attempts,
  int last_signum);

/// Increments ref count of the managed process preventing disposition of process related
/// data structure until ref count became zero.
IW_EXPORT void iwn_proc_ref(pid_t pid);

/// Decrements ref count of the manage process.
IW_EXPORT void iwn_proc_unref(pid_t pid);

/// Dispose process management module releasing out all memory resources.
IW_EXPORT void iwn_proc_dispose(void);

/// Returns process spawn command.
/// @note Returned value should be released by `free()`.
IW_EXPORT IW_ALLOC char* iwn_proc_command_get(const struct iwn_proc_spec *spec);

IW_EXTERN_C_END

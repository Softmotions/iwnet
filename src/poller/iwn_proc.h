#pragma once

/// Process management library.

#include "iwn_poller.h"

IW_EXTERN_C_START;

/// Process context available for process events callback.
struct iwn_proc_ctx {
  /// Child pid.
  pid_t pid;

  /// Child process wait status: `man 2 wait`
  int wstatus;

  /// Arbitrary user data.
  void *user_data;
};

struct iwn_proc_fork_child_ctx {
  const struct iwn_proc_ctx *ctx;
  int  comm_fds[4];
  void (*cmd_arg_append)(struct iwn_proc_fork_child_ctx *ctx, const char *arg);
  void (*cmd_arg_replace)(struct iwn_proc_fork_child_ctx *ctx, const char *arg, const char *replace);
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

  /// Data channel callback
  void (*on_dataout)(const struct iwn_proc_ctx *ctx, const char *buf, size_t len);

  /// On child process exit.
  void (*on_exit)(const struct iwn_proc_ctx *ctx_exit);

  /// On fork parent handler.
  iwrc (*on_fork_parent)(const struct iwn_proc_ctx *ctx, pid_t child_pid);

  /// On fork child handler.
  iwrc (*on_fork_child)(struct iwn_proc_fork_child_ctx *ctx);

  /// Sends a given signal to the child process if parent process exits.
  /// NOTE: Works only on Linux.
  int parent_death_signal;

  /// It true set the ability to write into stdin of the child process
  bool write_stdin;

  /// It true set the ability to write into data channel of the child process
  bool write_datain;

  /// If true use the PATH environment variable to locate exact path to the executable.
  bool find_executable_in_path;

  /// Starts the child process as a leader of its own session and process group
  /// (`setsid()` is called by this module before `on_fork_child`) and makes all the
  /// process management operations of this module cover the whole process group,
  /// that is the whole process tree of the child:
  ///  - ::iwn_proc_kill() and ::iwn_proc_kill_all() signal the process group;
  ///  - ::iwn_proc_wait(), ::iwn_proc_wait_timeout() and ::iwn_proc_wait_all()
  ///    complete only when the process group has no members left (the child leader
  ///    itself is reaped as usual, `on_exit` is called at its exit);
  ///  - ::iwn_proc_wait_fast() keeps the leader semantics: it completes as soon as
  ///    the child leader is reaped.
  /// The process group is considered to be finished when it is empty, so processes
  /// which detach from the group (for example daemons calling `setsid()`) do not
  /// prevent the completion. Such processes are not signalled any more.
  /// @note The child becomes a session leader, thus it has no controlling terminal.
  bool kill_process_group;
};

/// Spawn (fork) new process according to the given specification.
/// @param spec Process specification.
/// @param[out] Process `pid` holder.
///
IW_EXPORT iwrc iwn_proc_spawn(const struct iwn_proc_spec *spec, pid_t *out_pid);

/// Blocks current thread until the child process identified by `pid` became inactive.
/// If the process was started with `iwn_proc_spec::kill_process_group`, blocks until the
/// whole process group of the child became inactive.
IW_EXPORT iwrc iwn_proc_wait(pid_t pid);

/// Same as ::iwn_proc_wait(), but completes as soon as the child leader is reaped,
/// even if its process group (see `iwn_proc_spec::kill_process_group`) is still running.
IW_EXPORT iwrc iwn_proc_wait_fast(pid_t pid);

/// Waits until the child process identified by `pid` became inactive, but not longer than
/// `timeout_ms` milliseconds.
/// If the process was started with `iwn_proc_spec::kill_process_group`, waits until the
/// whole process group of the child became inactive.
/// @param pid Managed process pid.
/// @param timeout_ms Maximum wait time in milliseconds.
/// @param[out] out_timeout Set to `true` if the wait has timed out, `false` otherwise.
///             Optional, may be zero.
/// @return `0` on success.
IW_EXPORT iwrc iwn_proc_wait_timeout(pid_t pid, long timeout_ms, bool *out_timeout);

/// Waits until all the child processes identified by `pids` became inactive, but not longer
/// than `timeout_ms` milliseconds in total.
/// The processes started with `iwn_proc_spec::kill_process_group` are considered inactive
/// only when their whole process group is finished.
/// @param pids Array of the managed process pids. Pids equal to `-1` are ignored.
/// @param pids_num Number of pids in `pids`. At most 4096.
/// @param timeout_ms Maximum wait time in milliseconds.
/// @param[out] out_timeout Set to `true` if the wait has timed out, `false` otherwise.
///             Optional, may be zero.
/// @return `0` on success.
IW_EXPORT iwrc iwn_proc_wait_list_timeout(const pid_t *pids, int pids_num, long timeout_ms, bool *out_timeout);

/// Replaces the user data associated with the managed process.
/// @param pid Managed process pid.
/// @param data New user data, reported by `struct iwn_proc_ctx::user_data`.
/// @return `true` if the process is managed, `false` if it is not found.
IW_EXPORT bool iwn_proc_set_user_data(pid_t pid, void *data);

/// Blocks current thread until all child processes managed by this module became inactive.
/// The processes started with `iwn_proc_spec::kill_process_group` are considered inactive
/// only when their whole process group is finished.
IW_EXPORT void iwn_proc_wait_all(void);

/// Waits for all the child processes managed by this module to become inactive, awaiting at
/// most `timeout_ms` milliseconds in total.
/// The processes started with `iwn_proc_spec::kill_process_group` are considered inactive
/// only when their whole process group is finished.
/// @param timeout_ms Maximum wait time in milliseconds. Waits indefinitely if zero.
/// @param[out] out_timeout Set to `true` if the wait has timed out, `false` otherwise.
///             Must not be zero.
/// @return `0` on success.
IW_EXPORT iwrc iwn_proc_wait_all_timeout(long timeout_ms, bool *out_timeout);

/// Writes `buf` of size `len` into process standard input.
/// @param pid Process pid
/// @param buf Data buffer
/// @param len Data buffer length
/// @param close If `true` file descriptor of parent side will be closed after write.
///
IW_EXPORT iwrc iwn_proc_stdin_write(pid_t pid, const void *buf, size_t len, bool close);

/// Closes stdin write file descriptor on parent side.
IW_EXPORT iwrc iwn_proc_stdin_close(pid_t pid);

/// Writes `buf` of size `len` into process data input.
/// @param pid Process pid
/// @param buf Data buffer
/// @param len Data buffer length
/// @param close If `true` file descriptor of parent side will be closed after write.
///
IW_EXPORT iwrc iwn_proc_datain_write(pid_t pid, const char *buf, size_t len, bool close);

/// Closes datain write file descriptor on parent side.
IW_EXPORT iwrc iwn_proc_datain_close(pid_t pid);

/// Sends `signum` signal to the child process identified by `pid`.
/// If the process was started with `iwn_proc_spec::kill_process_group`, the signal is
/// sent to the whole process group of the child.
IW_EXPORT void iwn_proc_kill(pid_t pid, int signum);

/// Sends `signum` to all managed processes (and to their process groups if they were
/// started with `iwn_proc_spec::kill_process_group`).
IW_EXPORT void iwn_proc_kill_all(int signum);

/// Increments ref count of the managed process preventing disposition of process related
/// data structure until ref count became zero.
IW_EXPORT void iwn_proc_ref(pid_t pid);

/// Decrements ref count of the managed process.
IW_EXPORT void iwn_proc_unref(pid_t pid);

/// Dispose process management module releasing out all memory resources.
IW_EXPORT void iwn_proc_dispose(void);

/// Same as ::iwn_proc_dispose(), but sends the given `signal` to all the managed processes
/// (and to their process groups, see `iwn_proc_spec::kill_process_group`) and awaits their
/// completion for at most `timeout_ms` milliseconds before releasing the module resources.
/// @param signal Signal sent to the managed processes. `SIGKILL` is used if zero.
/// @param timeout_ms Maximum time to wait for the processes completion in milliseconds.
///                   Waits indefinitely if zero.
/// @return `true` if the processes did not complete within `timeout_ms`.
/// @note The module cannot be used after this call.
IW_EXPORT bool iwn_proc_dispose2(int signal, long timeout_ms);

/// Returns process spawn command.
/// @note Returned value should be released by `free()`.
IW_EXPORT IW_ALLOC char* iwn_proc_command_get(const struct iwn_proc_spec *spec);

/// Gets instant number of managed processes (including the process groups of the
/// processes started with `iwn_proc_spec::kill_process_group` which are still running).
IW_EXPORT int iwn_proc_num_managed(void);

IW_EXTERN_C_END;

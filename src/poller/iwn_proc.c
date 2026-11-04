#include "iwn_proc.h"
#include "iwn_scheduler.h"

#include <iowow/iwlog.h>
#include <iowow/iwth.h>
#include <iowow/iwp.h>
#include <iowow/iwhmap.h>
#include <iowow/iwutils.h>
#include <iowow/iwstw.h>
#include <iowow/iwpool.h>
#include <iowow/iwxstr.h>
#include <iowow/iwarr.h>

#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <pthread.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <stddef.h>
#include <string.h>
#include <time.h>

#ifdef __linux__
#include <sys/prctl.h>
#endif

#ifdef __APPLE__
#include <crt_externs.h>
#define environ (*_NSGetEnviron())
#else
extern char **environ;
#endif

#define FDS_STDOUT  0
#define FDS_STDERR  1
#define FDS_STDIN   2
#define FDS_DATAOUT 3
#define FDS_DATAIN  4

/// Interval of the process group drain checks.
#define PROC_PG_POLL_MS 50

struct proc {
  // The leading fields must match `struct iwn_proc_ctx`: the callbacks receive
  // the `struct proc` instance cast to `const struct iwn_proc_ctx*`.
  pid_t pid;
  int   wstatus;
  void *user_data;

  volatile int refs;
  char *path;
  struct iwulist argl;

  char **envp;
  struct iwpool       *pool;
  struct iwxstr       *buf_stdin;
  struct iwxstr       *buf_datain;
  struct iwn_proc_spec spec;

  int fds[5]; // {stdout, stderr, stdin, datain, dataout}
  pthread_mutex_t mtx;
  pid_t pgid; ///< Process group id of the child, `-1` if the group is not managed
  bool exited;
};

static_assert(offsetof(struct proc, pid) == offsetof(struct iwn_proc_ctx, pid),
              "struct proc must extend struct iwn_proc_ctx");
static_assert(offsetof(struct proc, wstatus) == offsetof(struct iwn_proc_ctx, wstatus),
              "struct proc must extend struct iwn_proc_ctx");
static_assert(offsetof(struct proc, user_data) == offsetof(struct iwn_proc_ctx, user_data),
              "struct proc must extend struct iwn_proc_ctx");

static struct  {
  struct iwhmap  *map;  ///< Proc: pid -> struct *_proc
  struct iwstw   *stw;  ///< Child process wait worker
  struct iwulist  pg_drain; ///< struct _pg_drain_entry: released processes with a running group
  pthread_t       pg_reaper;
  bool            pg_reaper_created;
  bool            pg_reaper_running;
  pthread_mutex_t mtx;
  pthread_mutex_t spawn_mtx;
  pthread_cond_t  cond;
} cc = {
  .mtx = PTHREAD_MUTEX_INITIALIZER,
  .spawn_mtx = PTHREAD_MUTEX_INITIALIZER,
};

/// A released managed process whose process group is still running.
struct _pg_drain_entry {
  pid_t pid;  ///< Child leader pid
  pid_t pgid; ///< Process group id
};

static void _proc_destroy(struct proc *proc) {
  if (!proc) {
    return;
  }
  for (int i = 0; i < sizeof(proc->fds) / sizeof(proc->fds[0]); ++i) {
    if (proc->fds[i] != -1) {
      iwn_poller_remove(proc->spec.poller, proc->fds[i]);
      proc->fds[i] = -1;
    }
  }
  iwxstr_destroy(proc->buf_stdin);
  iwxstr_destroy(proc->buf_datain);
  iwulist_destroy_keep(&proc->argl);
  pthread_mutex_destroy(&proc->mtx);
  iwpool_destroy(proc->pool);
}

static void _kv_free(void *key, void *val) {
  _proc_destroy(val);
}

static iwrc _init_lk(void) {
  static bool init = false;
  iwrc rc = 0;
  if (__sync_bool_compare_and_swap(&init, false, true)) {
    pthread_condattr_t cattr;
    pthread_condattr_init(&cattr);
#if defined(CLOCK_MONOTONIC) && !defined(__APPLE__)
    // The condition variable clock must match the clock used by
    // `iw_cond_timed_wait_ms()` to compute wait deadlines: it uses `CLOCK_MONOTONIC`
    // on platforms providing `pthread_condattr_setclock()` (iowow >= 1.7.3) and the
    // wall clock otherwise. Apple defines `CLOCK_MONOTONIC` but does not provide
    // `pthread_condattr_setclock()`, so both sides use `CLOCK_REALTIME` there.
    pthread_condattr_setclock(&cattr, CLOCK_MONOTONIC);
#endif
    pthread_cond_init(&cc.cond, &cattr);
    pthread_condattr_destroy(&cattr);
    RCB(finish, cc.map = iwhmap_create_u32(_kv_free));
    RCC(rc, finish, iwulist_init(&cc.pg_drain, 8, sizeof(struct _pg_drain_entry)));
    rc = iwstw_start("proc_stw", 0, false, &cc.stw);
  }
finish:
  return rc;
}

static iwrc _proc_add(struct proc *proc) {
  iwrc rc = 0;
  pthread_mutex_lock(&cc.mtx);
  RCC(rc, finish, _init_lk());
  proc->refs = 1;
  RCC(rc, finish, iwhmap_put_u32(cc.map, proc->pid, proc));
  pthread_cond_broadcast(&cc.cond);

finish:
  pthread_mutex_unlock(&cc.mtx);
  return rc;
}

static struct proc* _proc_ref(pid_t pid) {
  struct proc *proc;
  pthread_mutex_lock(&cc.mtx);
  proc = cc.map ? iwhmap_get_u32(cc.map, pid) : 0;
  if (proc) {
    if (proc->refs == 0) {
      proc = 0; // proc has been removed
    } else {
      proc->refs++;
    }
  }
  pthread_mutex_unlock(&cc.mtx);
  return proc;
}

/// @return `true` if the process group `pgid` is still running and can be signalled.
static bool _proc_pg_exists(pid_t pgid) {
  // A process group id is reusable only when the group is empty, so `EPERM` (the group is
  // owned by another user) means that our group is already gone.
  return kill(-pgid, 0) == 0;
}

/// Removes the process from the registry of the managed processes.
/// Must be called with `cc.mtx` held.
static void _proc_remove_lk(pid_t pid) {
  if (cc.map) {
    iwhmap_remove_u32(cc.map, pid);
  }
  pthread_cond_broadcast(&cc.cond);
}

/// Reaper of the process groups which outlived their leaders: the process remains
/// registered until its group is empty, so the whole process tree can be signalled
/// and the wait operations complete only when the tree is finished.
static void* _proc_pg_reaper(void *arg) {
  iwp_set_current_thread_name("proc_pg_reaper");
  pthread_mutex_lock(&cc.mtx);
  while (cc.map) {
    for (int i = iwulist_length(&cc.pg_drain) - 1; i >= 0; --i) {
      struct _pg_drain_entry *e = iwulist_get(&cc.pg_drain, i);
      if (_proc_pg_exists(e->pgid)) {
        continue;
      }
      pid_t pid = e->pid;
      iwulist_remove(&cc.pg_drain, i);
      _proc_remove_lk(pid);
    }
    if (!iwulist_length(&cc.pg_drain)) {
      break;
    }
    bool bv = false;
    iw_cond_timed_wait_ms(&cc.cond, &cc.mtx, PROC_PG_POLL_MS, &bv);
  }
  cc.pg_reaper_running = false;
  pthread_mutex_unlock(&cc.mtx);
  return 0;
}

/// Adds the released process to the list of the process groups awaiting drain and
/// starts the group reaper if it is not running.
/// Must be called with `cc.mtx` held.
static void _proc_pg_drain_add_lk(pid_t pid, pid_t pgid) {
  struct _pg_drain_entry e = { .pid = pid, .pgid = pgid };

  iwrc rc = iwulist_push(&cc.pg_drain, &e);
  if (rc) {
    iwlog_ecode_error3(rc);
    _proc_remove_lk(pid);
    return;
  }
  if (cc.pg_reaper_running) {
    pthread_cond_broadcast(&cc.cond);
    return;
  }
  if (cc.pg_reaper_created) {
    // The previous reaper has already finished (it resets `pg_reaper_running` while
    // holding `cc.mtx`), release its resources before starting a new one.
    pthread_join(cc.pg_reaper, 0);
    cc.pg_reaper_created = false;
  }
  cc.pg_reaper_running = true;
  pthread_cond_broadcast(&cc.cond);
  int rci = pthread_create(&cc.pg_reaper, 0, _proc_pg_reaper, 0);
  if (rci) {
    cc.pg_reaper_running = false;
    iwlog_ecode_error2(iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rci),
                       "proc | Failed to start the process group reaper");
    iwulist_remove(&cc.pg_drain, iwulist_length(&cc.pg_drain) - 1);
    _proc_remove_lk(pid);
    return;
  }
  cc.pg_reaper_created = true;
}

static void _proc_unref(pid_t pid, int wstatus) {
  struct proc *proc = 0;
  pthread_mutex_lock(&cc.mtx);
  proc = cc.map ? iwhmap_get_u32(cc.map, pid) : 0;
  if (!proc || proc->refs == 0) {
    pthread_mutex_unlock(&cc.mtx);
    return;
  }
  proc->refs--;
  if (wstatus != -1) {
    proc->wstatus = wstatus;
    pthread_cond_broadcast(&cc.cond); // Notify `iwn_proc_wait_fast()` waiters
  }
  if (proc->refs > 0) {
    pthread_mutex_unlock(&cc.mtx);
    return;
  }
  const pid_t pgid = proc->pgid;
  pthread_mutex_unlock(&cc.mtx);

  // Now shutdown proc instance
  for (int i = 0; i < sizeof(proc->fds) / sizeof(proc->fds[0]); ++i) {
    if (proc->fds[i] != -1) {
      iwn_poller_remove(proc->spec.poller, proc->fds[i]);
      proc->fds[i] = -1;
    }
  }

  if (proc->spec.on_exit) {
    proc->spec.on_exit((void*) proc);
  }

  pthread_mutex_lock(&cc.mtx);
  if (!cc.map) { // The module has been disposed
    pthread_mutex_unlock(&cc.mtx);
    return;
  }
  if (pgid > 0 && _proc_pg_exists(pgid)) {
    // The child leader is reaped, but its process group is still running: the process
    // remains registered until the group is empty.
    _proc_pg_drain_add_lk(pid, pgid);
  } else {
    _proc_remove_lk(pid);
  }
  pthread_mutex_unlock(&cc.mtx);
}

void iwn_proc_ref(pid_t pid) {
  _proc_ref(pid);
}

void iwn_proc_unref(pid_t pid) {
  _proc_unref(pid, -1);
}

static void _proc_wait_worker(void *arg) {
  while (cc.map) { // FIXME
    int wstatus = 0;
    pid_t pid = wait(&wstatus);
    if (pid != -1 && (WIFEXITED(wstatus) || WIFSIGNALED(wstatus))) { // No child processes or shutdown
      _proc_unref(pid, wstatus);
    } else {
      return;
    }
  }
}

static struct proc* _proc_create(const struct iwn_proc_spec *spec) {
  struct iwpool *pool = iwpool_create(sizeof(struct proc));
  if (!pool) {
    return 0;
  }
  struct proc *proc = iwpool_calloc(sizeof(*proc), pool);
  if (!proc) {
    iwpool_destroy(pool);
    return 0;
  }
  iwulist_init(&proc->argl, 8, sizeof(char*));
  pthread_mutex_init(&proc->mtx, 0);
  proc->pool = pool;
  proc->pid = -1;
  proc->pgid = -1;
  proc->wstatus = -1;
  proc->user_data = spec->user_data;
  memcpy(&proc->spec, spec, sizeof(*spec));
  for (int i = 0; i < sizeof(proc->fds) / sizeof(proc->fds[0]); ++i) {
    proc->fds[i] = -1;
  }
  return proc;
}

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

static iwrc _proc_init(struct proc *proc, int fds[10]) {
  iwrc rc = 0;
  struct iwn_proc_spec *spec = &proc->spec;
  struct iwpool *pool = proc->pool;

  proc->path = iwpool_strdup(pool, spec->path, &rc);
  RCGO(rc, finish);

  iwulist_push(&proc->argl, &proc->path);
  if (spec->args) {
    for (const char **v = spec->args; *v; ++v) {
      iwulist_push(&proc->argl, v);
    }
  }

  if (spec->env) {
    int i = 0;
    while (spec->env[i]) ++i;
    RCB(finish, proc->envp = iwpool_alloc((i + 1) * sizeof(spec->env[0]), pool));
    proc->envp[i] = 0;
    while (--i >= 0) {
      RCB(finish, proc->envp[i] = iwpool_strdup2(pool, spec->env[i]));
    }
  } else {
    proc->envp = 0;
  }

  if (spec->on_stdout) {
    RCN(finish, pipe(&fds[0]));
    proc->fds[FDS_STDOUT] = fds[0];
    RCC(rc, finish, _make_non_blocking(fds[0]));
  }
  if (spec->on_stderr) {
    RCN(finish, pipe(&fds[2]));
    proc->fds[FDS_STDERR] = fds[2];
    RCC(rc, finish, _make_non_blocking(fds[2]));
  }
  if (spec->write_stdin) {
    RCN(finish, pipe(&fds[4]));
    proc->fds[FDS_STDIN] = fds[5];
    RCC(rc, finish, _make_non_blocking(fds[5]));
  }
  if (spec->on_dataout) {
    RCN(finish, pipe(&fds[6]));
    proc->fds[FDS_DATAOUT] = fds[6];
    RCC(rc, finish, _make_non_blocking(fds[6]));
  }
  if (spec->write_datain) {
    RCN(finish, pipe(&fds[8]));
    proc->fds[FDS_DATAIN] = fds[9];
    RCC(rc, finish, _make_non_blocking(fds[9]));
  }

finish:
  return rc;
}

static int64_t _on_ready(
  const struct iwn_poller_task *t,
  uint32_t                      flags,
  int                           fdi) {
  iwrc rc = 0;
  int64_t ret = 0;
  int fd = t->fd;
  pid_t pid = (pid_t) (intptr_t) t->user_data;
  struct proc *proc = _proc_ref(pid);

  if (!proc) {
    return -1;
  }

  struct iwxstr *xstr;
  RCB(finish, xstr = iwxstr_create_empty());

  while (!rc) {
    char buf[1024];
    ssize_t rci = read(fd, buf, sizeof(buf));
    if (rci == -1) {
      if (errno == EINTR) {
        continue;
      } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
        break;
      }
      rc = iwrc_set_errno(IW_ERROR_IO_ERRNO, errno);
      break;
    } else if (rci == 0) {
      ret = -1;
      break;
    }
    rc = iwxstr_cat(xstr, buf, rci);
  }

  if (iwxstr_size(xstr) > 0) {
    switch (fdi) {
      case FDS_STDERR:
        proc->spec.on_stderr((void*) proc, iwxstr_ptr(xstr), iwxstr_size(xstr));
        break;
      case FDS_STDOUT:
        proc->spec.on_stdout((void*) proc, iwxstr_ptr(xstr), iwxstr_size(xstr));
        break;
      case FDS_DATAOUT:
        proc->spec.on_dataout((void*) proc, iwxstr_ptr(xstr), iwxstr_size(xstr));
        break;
    }
  }

finish:
  iwxstr_destroy(xstr);
  if (rc) {
    iwlog_ecode_error3(rc);
  }
  _proc_unref(pid, -1);
  return rc ? -1 : ret;
}

static void _on_fd_dispose(const struct iwn_poller_task *t) {
  pid_t pid = (pid_t) (intptr_t) t->user_data;
  struct proc *proc = _proc_ref(pid);
  if (proc) {
    for (int i = 0; i < sizeof(proc->fds) / sizeof(proc->fds[0]); ++i) {
      if (proc->fds[i] == t->fd) {
        proc->fds[i] = -1;
        break;
      }
    }
    _proc_unref(pid, -1);
  }
  _proc_unref(pid, -1);
}

static int64_t _on_stdout_ready(const struct iwn_poller_task *t, uint32_t flags) {
  return _on_ready(t, flags, FDS_STDOUT);
}

static int64_t _on_stderr_ready(const struct iwn_poller_task *t, uint32_t flags) {
  return _on_ready(t, flags, FDS_STDERR);
}

static int64_t _on_dataout_ready(const struct iwn_poller_task *t, uint32_t flags) {
  return _on_ready(t, flags, FDS_DATAOUT);
}

static int64_t _on_in_write(const struct iwn_poller_task *t, uint32_t flags, int mode) {
  iwrc rc = 0;
  int64_t ret = 0;
  int fd = t->fd;
  pid_t pid = (pid_t) (intptr_t) t->user_data;
  struct proc *proc = _proc_ref(pid);
  if (!proc) {
    return -1;
  }
  struct iwxstr *buf = mode == 0 ? proc->buf_stdin : proc->buf_datain;
  while (1) {
    pthread_mutex_lock(&proc->mtx);
    if (!buf) {
      pthread_mutex_unlock(&proc->mtx);
      break;
    }
    if (iwxstr_size(buf) == 0) {
      if ((intptr_t) iwxstr_user_data_get(buf) == 1) { // Close th channel
        ret = -1;
      }
      pthread_mutex_unlock(&proc->mtx);
      break;
    }
    int rci = write(fd, iwxstr_ptr(buf), iwxstr_size(buf));
    if (rci == -1) {
      if (errno == EINTR) {
        pthread_mutex_unlock(&proc->mtx);
        continue;
      } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
        ret = IWN_POLLOUT;
        pthread_mutex_unlock(&proc->mtx);
        break;
      }
      rc = iwrc_set_errno(IW_ERROR_IO_ERRNO, errno);
      pthread_mutex_unlock(&proc->mtx);
      break;
    } else if (rci == 0) {
      pthread_mutex_unlock(&proc->mtx);
      ret = -1;
      break;
    }
    iwxstr_shift(buf, rci);
    pthread_mutex_unlock(&proc->mtx);
  }
  _proc_unref(pid, -1);
  ret = rc ? -1 : ret;
  return ret;
}

static int64_t _on_stdin_write(const struct iwn_poller_task *t, uint32_t flags) {
  return _on_in_write(t, flags, 0);
}

static int64_t _on_datain_write(const struct iwn_poller_task *t, uint32_t flags) {
  return _on_in_write(t, flags, 1);
}

iwrc iwn_proc_stdin_write(pid_t pid, const void *buf, size_t len, bool close) {
  iwrc rc = 0;
  struct proc *proc = _proc_ref(pid);
  if (!proc) {
    return IW_ERROR_NOT_EXISTS;
  }
  pthread_mutex_lock(&proc->mtx);
  if (!proc->buf_stdin) {
    RCB(finish, proc->buf_stdin = iwxstr_create(len));
  }
  if (len > 0) {
    RCC(rc, finish, iwxstr_cat(proc->buf_stdin, buf, len));
  }
  if (close) {
    iwxstr_user_data_set(proc->buf_stdin, (void*) (intptr_t) 1, 0);
  }
  rc = iwn_poller_arm_events(proc->spec.poller, proc->fds[FDS_STDIN], IWN_POLLOUT);

finish:
  pthread_mutex_unlock(&proc->mtx);
  _proc_unref(pid, -1);
  return rc;
}

iwrc iwn_proc_stdin_close(pid_t pid) {
  return iwn_proc_stdin_write(pid, "", 0, true);
}

iwrc iwn_proc_datain_write(pid_t pid, const char *buf, size_t len, bool close) {
  iwrc rc = 0;
  struct proc *proc = _proc_ref(pid);
  if (!proc) {
    return IW_ERROR_NOT_EXISTS;
  }
  pthread_mutex_lock(&proc->mtx);
  if (!proc->buf_datain) {
    RCB(finish, proc->buf_datain = iwxstr_create(len));
  }
  if (len > 0) {
    RCC(rc, finish, iwxstr_cat(proc->buf_datain, buf, len));
  }
  if (close) {
    iwxstr_user_data_set(proc->buf_datain, (void*) (intptr_t) 1, 0);
  }
  rc = iwn_poller_arm_events(proc->spec.poller, proc->fds[FDS_DATAIN], IWN_POLLOUT);

finish:
  pthread_mutex_unlock(&proc->mtx);
  _proc_unref(pid, -1);
  return rc;
}

iwrc iwn_proc_datain_close(pid_t pid) {
  return iwn_proc_datain_write(pid, "", 0, true);
}

static iwrc _proc_wait(pid_t pid, bool fast) {
  pthread_mutex_lock(&cc.mtx);
  struct proc *proc = cc.map ? iwhmap_get_u32(cc.map, pid) : 0;
  if (!proc || (proc->wstatus != -1 && fast)) {
    pthread_mutex_unlock(&cc.mtx);
    return 0;
  }
  do {
    pthread_cond_wait(&cc.cond, &cc.mtx);
    proc = cc.map ? iwhmap_get_u32(cc.map, pid) : 0;
    if (!proc || (proc->wstatus != -1 && fast)) {
      break;
    }
  } while (1);
  pthread_mutex_unlock(&cc.mtx);
  return 0;
}

iwrc iwn_proc_wait(pid_t pid) {
  return _proc_wait(pid, false);
}

iwrc iwn_proc_wait_fast(pid_t pid) {
  return _proc_wait(pid, true);
}

bool iwn_proc_set_user_data(pid_t pid, void *data) {
  pthread_mutex_lock(&cc.mtx);
  struct proc *proc = cc.map ? iwhmap_get_u32(cc.map, pid) : 0;
  if (proc) {
    proc->user_data = data;
    pthread_mutex_unlock(&cc.mtx);
    return true;
  }
  pthread_mutex_unlock(&cc.mtx);
  return false;
}

iwrc iwn_proc_wait_list_timeout(const pid_t *pids_, int pids_num, long timeout_ms, bool *out_timeout) {
  if (!pids_ || pids_num < 1) {
    return 0;
  }
  if (pids_num > 4096) {
    return IW_ERROR_INVALID_ARGS;
  }

  if (out_timeout) {
    *out_timeout = false;
  }

  iwrc rc = 0;
  int pids_towait = 0;
  long remaining = timeout_ms;
  pid_t pids[pids_num];

  for (int i = 0; i < pids_num; ++i) {
    if (pids_[i] != -1) {
      pids_towait++;
      pids[i] = pids_[i];
    } else {
      pids[i] = -1;
    }
  }

  pthread_mutex_lock(&cc.mtx);

  while (pids_towait > 0) {
    for (int i = 0; i < pids_num; ++i) {
      if (pids[i] != -1) {
        struct proc *proc = cc.map ? iwhmap_get_u32(cc.map, pids[i]) : 0;
        if (!proc) {
          pids[i] = -1;
          --pids_towait;
        }
      }
    }

    if (pids_towait < 1) {
      break;
    }

    if (remaining > 0) {
      bool bv = false;
      uint64_t ts1, ts2;

      RCC(rc, finish, iwp_current_time_ms(&ts1, true));
      RCC(rc, finish, iw_cond_timed_wait_ms(&cc.cond, &cc.mtx, remaining, &bv));
      if (bv) {
        if (out_timeout) {
          *out_timeout = true;
        }
        break;
      }

      RCC(rc, finish, iwp_current_time_ms(&ts2, true));
      remaining -= (ts2 - ts1);
      if (remaining < 1) {
        if (out_timeout) {
          *out_timeout = true;
        }
        break;
      }
    } else {
      RCT(finish, pthread_cond_wait(&cc.cond, &cc.mtx));
    }
  }

finish:
  pthread_mutex_unlock(&cc.mtx);
  return rc;
}

iwrc iwn_proc_wait_timeout(pid_t pid, long timeout_ms, bool *out_timeout) {
  return iwn_proc_wait_list_timeout((pid_t[]) { pid }, 1, timeout_ms, out_timeout);
}

void iwn_proc_wait_all(void) {
  pthread_mutex_lock(&cc.mtx);
  do {
    if (!cc.map || iwhmap_count(cc.map) == 0) {
      break;
    }
    pthread_cond_wait(&cc.cond, &cc.mtx);
  } while (1);
  pthread_mutex_unlock(&cc.mtx);
}

iwrc iwn_proc_wait_all_timeout(long timeout_ms, bool *out_timeout) {
  iwrc rc = 0;
  *out_timeout = false;
  long remaining = timeout_ms;

  if (timeout_ms < 1) {
    iwn_proc_wait_all();
    return 0;
  }

  pthread_mutex_lock(&cc.mtx);
  do {
    bool bv = false;
    uint64_t ts1, ts2;

    if (!cc.map || iwhmap_count(cc.map) == 0) {
      break;
    }

    rc = iwp_current_time_ms(&ts1, true);
    if (rc) {
      break;
    }

    rc = iw_cond_timed_wait_ms(&cc.cond, &cc.mtx, remaining, &bv);
    if (rc) {
      break;
    }

    if (bv) {
      *out_timeout = true;
      break;
    }

    if (!cc.map || iwhmap_count(cc.map) == 0) {
      break;
    }

    rc = iwp_current_time_ms(&ts2, true);
    if (rc) {
      break;
    }

    remaining -= (ts2 - ts1);
    if (remaining < 1) {
      *out_timeout = true;
      break;
    }
  } while (1);
  pthread_mutex_unlock(&cc.mtx);
  return rc;
}

void iwn_proc_kill(pid_t pid, int signum) {
  pid_t pgid = -1;

  pthread_mutex_lock(&cc.mtx);
  if (cc.map) {
    struct proc *proc = iwhmap_get_u32(cc.map, pid);
    if (proc) {
      pgid = proc->pgid;
    }
  }
  pthread_mutex_unlock(&cc.mtx);

  if (pgid > 0) {
    // Signal the whole process group of the managed process.
    // The process is removed from the registry when its group is empty, so the group
    // id cannot be reused by a foreign process group here.
    if (_proc_pg_exists(pgid)) {
      kill(-pgid, signum);
    }
    return;
  }
  kill(pid, signum);
}

/// Kill target of ::iwn_proc_kill_all().
struct _kill_target {
  pid_t pid;
  pid_t pgid;
};

void iwn_proc_kill_all(int signum) {
  struct _kill_target *targets = 0;

  pthread_mutex_lock(&cc.mtx);
  uint32_t len = cc.map ? iwhmap_count(cc.map) : 0;
  if (len == 0) {
    pthread_mutex_unlock(&cc.mtx);
    return;
  }
  targets = malloc((len + 1) * sizeof(*targets));
  if (!targets) {
    pthread_mutex_unlock(&cc.mtx);
    return;
  }
  struct iwhmap_iter it;
  iwhmap_iter_init(cc.map, &it);
  targets[len].pid = -1;
  while (iwhmap_iter_next(&it) && len > 0) {
    pid_t pid = (intptr_t) it.key;
    struct proc *proc = iwhmap_get_u32(cc.map, pid);
    --len;
    targets[len].pid = pid;
    targets[len].pgid = proc ? proc->pgid : -1;
  }
  pthread_mutex_unlock(&cc.mtx);

  for (int i = 0; targets[i].pid != -1; ++i) {
    if (targets[i].pgid > 0) {
      if (_proc_pg_exists(targets[i].pgid)) {
        kill(-targets[i].pgid, signum);
      }
    } else {
      kill(targets[i].pid, signum);
    }
  }
  free(targets);
}

struct ktask {
  int pid;
  int signum;
  int attempts;
  int last_signum;
  struct iwn_poller *poller;
};

static void _kill_ensure_task_cancel(void *arg) {
  struct ktask *t = arg;
  free(t);
}

static void _kill_ensure_task(void *arg) {
  struct ktask *t = arg;
  assert(t);
  int pid = t->pid;
  if (getpgid(pid) == -1) {
    free(t);
    return;
  }
  if (--t->attempts < 1) {
    iwlog_warn("Last killing attempt, pid: %d, signal: %d", pid, t->last_signum);
    kill(pid, t->last_signum);
    free(t);
    return;
  }
  kill(pid, t->signum);
  iwrc rc = iwn_schedule(&(struct iwn_scheduler_spec) {
    .poller = t->poller,
    .timeout_ms = 1000,
    .user_data = t,
    .task_fn = _kill_ensure_task,
    .on_cancel = _kill_ensure_task_cancel,
  });
  if (rc) {
    iwlog_ecode_error3(rc);
    free(t);
  }
}

static void _fork_child_cmd_arg_append(struct iwn_proc_fork_child_ctx *fcc, const char *arg) {
  struct proc *proc = (void*) fcc->ctx;
  if (arg) {
    char *v = iwpool_strdup2(proc->pool, arg);
    if (v) {
      iwulist_push(&proc->argl, &v);
    }
  }
}

static void _fork_child_cmd_arg_replace(struct iwn_proc_fork_child_ctx *fcc, const char *arg, const char *replace) {
  if (!arg || !replace) {
    return;
  }
  struct proc *proc = (void*) fcc->ctx;
  struct iwulist *list = &proc->argl;
  for (int i = 0, l = iwulist_length(list); i < l; ++i) {
    const char **item = iwulist_at2(list, i);
    if (strcmp(*item, arg) == 0) {
      char *v = iwpool_strdup2(proc->pool, replace);
      if (v) {
        *item = v;
      }
      break;
    }
  }
}

iwrc iwn_proc_spawn(const struct iwn_proc_spec *spec, pid_t *out_pid) {
  iwrc rc = 0;
  if (!spec || !spec->path || !spec->poller || !out_pid) {
    return IW_ERROR_INVALID_ARGS;
  }

  *out_pid = -1;

  bool bv, proc_added = false;
  struct proc *proc = 0;
  int fds[10] = { -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 };

  int rci = pthread_mutex_lock(&cc.spawn_mtx);
  if (rci) {
    return iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rci);
  }

  RCB(finish, proc = _proc_create(spec));
  RCC(rc, finish, _proc_init(proc, fds));

#ifdef __linux__
  pid_t ppid = getpid();
#endif
  pid_t pid = fork();

  if (pid > 0) { // Parent
    *out_pid = pid;
    proc->pid = pid;
    proc->pgid = spec->kill_process_group ? pid : -1;

    rc = _proc_add(proc);
    if (!rc) {
      rc = iwstw_schedule_empty_only(cc.stw, _proc_wait_worker, 0, &bv);
    }
    if (rc) {
      iwlog_ecode_error(rc, "proc | Killing %d due to the error", pid);
      kill(pid, SIGKILL);
      goto finish;
    }

    proc_added = true;

    if (fds[1] != -1) {
      close(fds[1]);
      rc = iwn_poller_add(&(struct iwn_poller_task) {
        .fd = fds[0],
        .user_data = (void*) (intptr_t) pid,
        .on_ready = _on_stdout_ready,
        .on_dispose = _on_fd_dispose,
        .events = IWN_POLLIN,
        .events_mod = IWN_POLLET,
        .poller = spec->poller
      });
      if (rc) {
        close(proc->fds[FDS_STDOUT]);
        proc->fds[FDS_STDOUT] = -1;
        iwlog_ecode_error3(rc);
        rc = 0;
      } else {
        _proc_ref(pid);
      }
    }
    if (fds[3] != -1) {
      close(fds[3]);
      rc = iwn_poller_add(&(struct iwn_poller_task) {
        .fd = fds[2],
        .user_data = (void*) (intptr_t) pid,
        .on_ready = _on_stderr_ready,
        .on_dispose = _on_fd_dispose,
        .events = IWN_POLLIN,
        .events_mod = IWN_POLLET,
        .poller = spec->poller
      });
      if (rc) {
        close(proc->fds[FDS_STDERR]);
        proc->fds[FDS_STDERR] = -1;
        iwlog_ecode_error3(rc);
        rc = 0;
      } else {
        _proc_ref(pid);
      }
    }
    if (fds[4] != -1) {
      close(fds[4]);
      rc = iwn_poller_add(&(struct iwn_poller_task) {
        .fd = fds[5],
        .user_data = (void*) (intptr_t) pid,
        .on_ready = _on_stdin_write,
        .events_mod = IWN_POLLET,
        .poller = spec->poller,
      });
      if (rc) {
        close(proc->fds[FDS_STDIN]);
        proc->fds[FDS_STDIN] = -1;
        iwlog_ecode_error3(rc);
        rc = 0;
      }
    }
    if (fds[7] != -1) {
      close(fds[7]);
      rc = iwn_poller_add(&(struct iwn_poller_task) {
        .fd = fds[6],
        .user_data = (void*) (intptr_t) pid,
        .on_ready = _on_dataout_ready,
        .on_dispose = _on_fd_dispose,
        .events = IWN_POLLIN,
        .events_mod = IWN_POLLET,
        .poller = spec->poller
      });
      if (rc) {
        close(proc->fds[FDS_DATAOUT]);
        proc->fds[FDS_DATAOUT] = -1;
        iwlog_ecode_error3(rc);
        rc = 0;
      } else {
        _proc_ref(pid);
      }
    }
    if (fds[8] != -1) {
      close(fds[8]);
      rc = iwn_poller_add(&(struct iwn_poller_task) {
        .fd = fds[9],
        .user_data = (void*) (intptr_t) pid,
        .on_ready = _on_datain_write,
        .events_mod = IWN_POLLET,
        .poller = spec->poller,
      });
      if (rc) {
        close(proc->fds[FDS_DATAIN]);
        proc->fds[FDS_DATAIN] = -1;
        iwlog_ecode_error3(rc);
        rc = 0;
      }
    }

    if (spec->on_fork_parent) {
      RCC(rc, finish, spec->on_fork_parent((void*) proc, pid));
    }
  } else if (pid == 0) { // Child
#ifdef __linux__
    if (spec->parent_death_signal) {
      int rci = prctl(PR_SET_PDEATHSIG, spec->parent_death_signal);
      if (rci == -1) {
        iwlog_ecode_error3(IW_ERROR_ERRNO);
        exit(1);
      }
      if (getppid() != ppid) {
        exit(1);
      }
    }
#endif

    if (spec->kill_process_group) {
      // The child becomes a leader of its own session and process group, thus the whole
      // process tree can be signalled by the group id which is equal to the child pid.
      if (setsid() == -1 && setpgid(0, 0) == -1) {
        _exit(1);
      }
    }

    if (spec->on_fork_child) {
      struct iwn_proc_fork_child_ctx fcc = {
        .ctx = (void*) proc,
        .comm_fds = { fds[6], fds[7], fds[8], fds[9] },
        .cmd_arg_append = _fork_child_cmd_arg_append,
        .cmd_arg_replace = _fork_child_cmd_arg_replace,
      };
      RCC(rc, child_exit, spec->on_fork_child(&fcc));
    }

    if (fds[1] != -1) {
      while ((dup2(fds[1], STDOUT_FILENO) == -1) && (errno == EINTR));
      close(fds[0]);
      close(fds[1]);
    }
    if (fds[3] != -1) {
      while ((dup2(fds[3], STDERR_FILENO) == -1) && (errno == EINTR));
      close(fds[2]);
      close(fds[3]);
    }
    if (fds[4] != -1) {
      while ((dup2(fds[4], STDIN_FILENO) == -1) && (errno == EINTR));
      close(fds[4]);
      close(fds[5]);
    }
    if (fds[6] != -1) { // DATAOUT
      close(fds[6]);
    }
    if (fds[9] != -1) { // DATAIN
      close(fds[9]);
    }

    if (spec->env) {
      environ = proc->envp;
    }

    {
      int l = iwulist_length(&proc->argl);
      char *argv[l + 1];
      argv[l] = 0;
      for (int i = 0; i < l; ++i) {
        argv[i] = *(char**) iwulist_get(&proc->argl, i);
      }

      if (spec->find_executable_in_path) {
        RCN(child_exit, execvp(proc->path, argv));
      } else {
        RCN(child_exit, execv(proc->path, argv));
      }
    }

    goto child_exit;
  } else {
    rc = iwrc_set_errno(IW_ERROR_ERRNO, errno);
  }

finish:
  pthread_mutex_unlock(&cc.spawn_mtx);
  if (rc) {
    if (!proc_added) {
      _proc_destroy(proc);
    }
  }
  return rc;

child_exit:
  if (rc) {
    iwlog_ecode_error(rc, "exec: %s", proc->path);
  }
  _exit(1);

}

char* iwn_proc_command_get(const struct iwn_proc_spec *spec) {
  struct iwxstr *xstr = iwxstr_create_empty();
  if (!xstr) {
    return 0;
  }
  if (spec->path) {
    iwxstr_cat2(xstr, spec->path);
  }
  int i = 0;
  for (const char *arg = spec->args[0]; arg; arg = spec->args[++i]) {
    iwxstr_cat(xstr, " ", 1);
    iwxstr_cat2(xstr, arg);
  }
  return iwxstr_destroy_keep_ptr(xstr);
}

bool iwn_proc_dispose2(int signal, long timeout_ms) {
  bool timeout = false;
  struct iwhmap *map = 0;
  iwn_proc_kill_all(signal ? signal : SIGKILL);
  iwrc rc = iwn_proc_wait_all_timeout(timeout_ms, &timeout);
  if (rc) {
    iwlog_ecode_error3(rc);
  }
  pthread_mutex_lock(&cc.mtx);
  map = cc.map;
  cc.map = 0;
  bool pg_reaper_created = cc.pg_reaper_created;
  pthread_cond_broadcast(&cc.cond);
  pthread_mutex_unlock(&cc.mtx);

  if (pg_reaper_created) {
    // The reaper exits as soon as it sees that the module has been disposed.
    pthread_join(cc.pg_reaper, 0);
    cc.pg_reaper_created = false;
  }
  iwulist_destroy_keep(&cc.pg_drain);
  iwstw_shutdown(&cc.stw, false);
  iwhmap_destroy(map);
  pthread_mutex_destroy(&cc.mtx);
  pthread_mutex_destroy(&cc.spawn_mtx);
  pthread_cond_destroy(&cc.cond);
  return timeout;
}

void iwn_proc_dispose(void) {
  iwn_proc_dispose2(0, 0);
}

int iwn_proc_num_managed(void) {
  if (!cc.map) {
    return 0;
  }
  int ret = 0;
  pthread_mutex_lock(&cc.mtx);
  ret = iwhmap_count(cc.map);
  pthread_mutex_unlock(&cc.mtx);
  return ret;
}

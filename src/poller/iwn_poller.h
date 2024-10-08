#pragma once

/// File/socket/etc descriptors polling reactor.
///
/// - On Linux `epoll` used.
/// - On Apple, FreeBSD `kqueue` used.

#include <iowow/basedefs.h>

#include <pthread.h>
#include <stdint.h>

IW_EXTERN_C_START;

#if defined(__FreeBSD__) || defined(__APPLE__) || defined(__NetBSD__) || defined(__OpenBSD__)
#define IWN_KQUEUE
#endif

/// @defgroup iwn_poller_flags
/// @{

/// Poller will do oneshot execution of `on_ready()` handler
/// after the period of time in milliseconds specified in `iwn_poller_task::timeout` field.
#define IWN_POLLTIMEOUT (1U << 21)

#ifdef __linux__
#define IWN_EPOLL
#include <sys/epoll.h>
#define IWN_POLLIN      EPOLLIN
#define IWN_POLLOUT     EPOLLOUT
#define IWN_POLLONESHOT EPOLLONESHOT
#define IWN_POLLET      EPOLLET
#elif defined(IWN_KQUEUE)
#define IWN_POLLIN      0x01U
#define IWN_POLLOUT     0x02U
#define IWN_POLLONESHOT 0x04U
#define IWN_POLLET      0x08U
#else
#error "Unsupported operating system"
#endif

/// Start poller loop even with no managed fds.
#define IWN_POLLER_POLL_NO_FDS 0x01U

/// @}

struct iwn_poller;

typedef void (*iwn_poller_destroy_hook)(struct iwn_poller*);

/// File descriptor poller monitoring task.
struct iwn_poller_task {
  int      fd;                                                   ///< File descriptor beeng polled
  void    *user_data;                                            ///< Arbitrary user data associated with poller_task
  int64_t  (*on_ready)(const struct iwn_poller_task*, uint32_t); ///< On fd event ready
  void     (*on_dispose)(const struct iwn_poller_task*);         ///< On destroy handler
  uint32_t events;                                               ///< Initial poll monitoring events
  uint32_t events_mod;                                           ///< Extra event flags added for every poll rearm
  long     timeout;                                              ///< Max event channel inactivity timeout in seconds.
                                                                 ///  Or timeout in milliseconds in IWN_POLLTIMEOUT
                                                                 ///  mode.
  struct iwn_poller *poller;                                     ///< Poller
};

struct iwn_poller_spec {
  /// Number of threads to process polled events.
  /// Number of cpu cores if zero.
  /// Default: 2, Max: 1024
  int num_threads;

  /// Max number of events to take for each poll iteration.
  /// Default: 1, Max: 128
  int one_shot_events;

  /// Default: 0, Max: 2
  /// @see iwtp_spec::overflow_threads_factor
  int overflow_threads_factor;

  /// Default: 0 (unlimited)
  /// @see iwtp_spec::queue_limit
  int queue_limit;

  /// Poller operational flags.
  /// Bitmask of following:
  ///   - IWN_POLLER_POLL_NO_FDS
  unsigned flags;

  /// @see iwtp_spec::warn_on_overflow_thread_spawn
  bool warn_on_overflow_thread_spawn;
};

/// Function executed in context of polled file descriptor.
typedef void (*iwn_poller_probe_fn)(struct iwn_poller*, void *slot_user_data, void *fn_user_data);

/// Creates a poller instance.
///
/// Returned poller pointer should be disposed by `iwn_poller_destroy()`.
IW_EXPORT iwrc iwn_poller_create_by_spec(const struct iwn_poller_spec *spec, struct iwn_poller **out_spec);

/// Creates a poller instance.
///
/// Returned poller pointer should be disposed by `iwn_poller_destroy()`.
///
/// @param num_threads Number of threads to process polled events.
///                    If zero number of cpu cores will be used.
/// @param one_shot_events Max number of events to take for each poll iteration.
///                        If zero fallback value will be used.
/// @param[out] Output poller holder.
///
IW_EXPORT iwrc iwn_poller_create(int num_threads, int one_shot_events, struct iwn_poller **out_poller);

/// Registers polling fd task.
IW_EXPORT iwrc iwn_poller_add(const struct iwn_poller_task *task);

IW_EXPORT iwrc iwn_poller_add2(const struct iwn_poller_task *task, int *out_fd);

/// Returns true if the given `fd` managed by poller.
IW_EXPORT bool iwn_poller_fd_is_managed(struct iwn_poller*, int fd);

IW_EXPORT bool iwn_poller_fd_ref(struct iwn_poller*, int fd, int refs);

/// Activates a set of `events` defined by @ref iwn_poller_flags on managed `fd`.
IW_EXPORT iwrc iwn_poller_arm_events(struct iwn_poller*, int fd, uint32_t events);

/// Set timeout for polled file descriptor.
IW_EXPORT void iwn_poller_set_timeout(struct iwn_poller*, int fd, long timeout_sec);

/// Remove `fd` from poller and dispose all associated resources.
IW_EXPORT void iwn_poller_remove(struct iwn_poller*, int fd);

/// Wake up a poller event loop.
IW_EXPORT void iwn_poller_poke(struct iwn_poller*);

/// Sends shutdown request to the specified poller.
IW_EXPORT void iwn_poller_shutdown_request(struct iwn_poller*);

/// Destroys poller install.
/// @note Current thread will be blocked until termination of all poller threads.
IW_EXPORT void iwn_poller_destroy(struct iwn_poller **pp);

/// Submits a poller task to the given poller.
IW_EXPORT iwrc iwn_poller_task(struct iwn_poller*, void (*task)(void*), void *arg);

/// Set one of the following poller flags:
/// - IWN_POLLER_POLL_NO_FDS - Start poller loop even with no managed fds.
//
IW_EXPORT void iwn_poller_flags_set(struct iwn_poller*, uint32_t flags);

/// Starts poller poll event loop.
/// @note Current thread will be blocked until event loop finished.
IW_EXPORT void iwn_poller_poll(struct iwn_poller*);

/// Starts poller poll event loop in separate thread.
IW_EXPORT iwrc iwn_poller_poll_in_thread(struct iwn_poller*, const char *thr_name, pthread_t *out_thr);

/// Returns `true` if poller event loop is alive.
IW_EXPORT bool iwn_poller_alive(struct iwn_poller*);

/// Runs a given `probe` callback in the context of polled filed descriptor `fd`.
/// All fd related data structures will be alive during callback call.
IW_EXPORT bool iwn_poller_probe(struct iwn_poller*, int fd, iwn_poller_probe_fn probe, void *fn_user_data);

IW_EXPORT iwrc iwn_poller_add_destroy_hook(struct iwn_poller*, iwn_poller_destroy_hook hook);

IW_EXTERN_C_END;

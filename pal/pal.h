/*
 * MXFS — Multinode XFS
 * Platform Abstraction Layer (PAL) interface
 *
 * Thin layer providing OS-specific primitives to libmxfs.
 * All libmxfs code uses PAL for: block I/O, threading, networking,
 * memory, time, logging, and SCSI PR.
 *
 * Each platform provides its own implementation of this interface:
 *   pal_linux_user.c  — Linux userspace (pthreads, POSIX sockets, O_DIRECT)
 *   pal_linux_kern.c  — Linux kernel (bio, kthread, kernel sockets)
 *   pal_macos.c       — macOS (IOKit, pthreads, POSIX sockets)
 *   pal_windows.c     — Windows (Win32 APIs, Winsock)
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0
 */

#ifndef MXFS_PAL_H
#define MXFS_PAL_H

#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/stddef.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/limits.h>
#ifndef UINT64_MAX
#define UINT64_MAX  U64_MAX
#endif
#ifndef UINT32_MAX
#define UINT32_MAX  U32_MAX
#endif
#ifndef INT64_MAX
#define INT64_MAX   S64_MAX
#endif
#else
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#endif

/* ─── Opaque types ─── */

typedef struct mxfs_bdev     mxfs_bdev_t;
typedef struct mxfs_thread   mxfs_thread_t;
typedef struct mxfs_mutex    mxfs_mutex_t;
typedef struct mxfs_spinlock mxfs_spinlock_t;
typedef struct mxfs_cond     mxfs_cond_t;
typedef struct mxfs_rwlock   mxfs_rwlock_t;
typedef struct mxfs_sock     mxfs_sock_t;

/* ─── Log levels ─── */

#define MXFS_LOG_DEBUG   0
#define MXFS_LOG_INFO    1
#define MXFS_LOG_WARN    2
#define MXFS_LOG_ERR     3

/* ─── Block device I/O ─── */

/*
 * Open a block device by path.
 * Returns NULL on failure.
 */
mxfs_bdev_t *mxfs_pal_bdev_open(const char *path);

/*
 * Close a block device.
 */
void mxfs_pal_bdev_close(mxfs_bdev_t *dev);

/*
 * Read len bytes from offset into buf.
 * Returns 0 on success, negative errno on failure.
 * The offset and len should be sector-aligned for O_DIRECT.
 */
int mxfs_pal_bdev_read(mxfs_bdev_t *dev, uint64_t offset,
                       void *buf, uint32_t len);

/*
 * Read len bytes from offset into buf with elevated I/O priority.
 * Uses REQ_PRIO | REQ_SYNC in kernel to prioritize over data I/O.
 * Use for DLM lock slot reads and other latency-sensitive metadata.
 * Returns 0 on success, negative errno on failure.
 */
int mxfs_pal_bdev_read_prio(mxfs_bdev_t *dev, uint64_t offset,
                             void *buf, uint32_t len);

/*
 * Write len bytes from buf to offset.
 * Returns 0 on success, negative errno on failure.
 */
int mxfs_pal_bdev_write(mxfs_bdev_t *dev, uint64_t offset,
                        const void *buf, uint32_t len);

/*
 * Write len bytes from buf to offset with Force Unit Access (FUA).
 * FUA bypasses the disk write cache, ensuring data is committed to
 * stable storage before the call returns. Use for multi-node I/O
 * coherency on shared block devices (e.g. VMware multi-writer VMDKs).
 * Returns 0 on success, negative errno on failure.
 */
int mxfs_pal_bdev_write_fua(mxfs_bdev_t *dev, uint64_t offset,
                             const void *buf, uint32_t len);

/*
 * Flush (fsync) the block device.
 * Returns 0 on success, negative errno on failure.
 */
int mxfs_pal_bdev_flush(mxfs_bdev_t *dev);

/*
 * Get the total size of a block device in bytes.
 * Returns 0 on success, negative errno on failure.
 */
int mxfs_pal_bdev_size(mxfs_bdev_t *dev, uint64_t *size_out);

/*
 * Write len bytes asynchronously using pipelined bio submission.
 * Submits up to 16 bios concurrently and waits for all completions.
 * Achieves real I/O parallelism vs submit_bio_wait's serial execution.
 * Intended for O_DIRECT data writes where iodepth > 1 matters.
 * Returns 0 on success, negative errno on failure.
 */
int mxfs_pal_bdev_write_async(mxfs_bdev_t *dev, uint64_t offset,
                               const void *buf, uint32_t len);

/*
 * Scatter write: submit multiple non-contiguous block writes concurrently.
 * Each entry is (offsets[i], bufs[i], lens[i]).  All BIOs are submitted
 * before waiting, allowing the I/O scheduler to merge and reorder.
 * Returns 0 on success, negative errno on first failure.
 */
int mxfs_pal_bdev_write_scatter(mxfs_bdev_t *dev,
                                 const uint64_t *offsets,
                                 void * const *bufs,
                                 const uint32_t *lens,
                                 int count);

/*
 * Read len bytes asynchronously using pipelined bio submission.
 * Same as mxfs_pal_bdev_read but explicitly named for symmetry with
 * write_async. Uses the same pipelined read path internally.
 * Returns 0 on success, negative errno on failure.
 */
int mxfs_pal_bdev_read_async(mxfs_bdev_t *dev, uint64_t offset,
                              void *buf, uint32_t len);

/*
 * Write multiple contiguous blocks to device in a single I/O.
 * bufs[] is an array of nbufs pointers, each pointing to blocksize bytes.
 * Blocks are written starting at offset. Returns 0 on success.
 */
int mxfs_pal_bdev_write_gather(mxfs_bdev_t *dev, uint64_t offset,
                                void **bufs, int nbufs,
                                uint32_t blocksize);

/*
 * Write multiple contiguous blocks to device in a single I/O with FUA.
 * Same as bdev_write_gather but forces write-through to stable storage.
 * Returns 0 on success, negative errno on failure.
 */
int mxfs_pal_bdev_write_gather_fua(mxfs_bdev_t *dev, uint64_t offset,
                                    void **bufs, int nbufs,
                                    uint32_t blocksize);

/*
 * Clone a block device handle with a base offset.
 * All I/O through the clone has base_offset added to the offset.
 * The clone shares the underlying device — the original owns it.
 * Returns NULL on failure.
 */
mxfs_bdev_t *mxfs_pal_bdev_clone_with_offset(mxfs_bdev_t *dev,
                                               uint64_t base_offset);

/*
 * Close a cloned block device handle.
 * Does NOT close the underlying device (owned by the original).
 */
void mxfs_pal_bdev_close_clone(mxfs_bdev_t *dev);

#ifdef __KERNEL__
struct block_device;
/*
 * Wrap an existing struct block_device * into a PAL bdev handle.
 * The wrapper does not own the device — free with mxfs_pal_bdev_close_clone().
 * Used by DLM integration to share the XFS-owned block device.
 */
mxfs_bdev_t *mxfs_pal_bdev_wrap(struct block_device *bdev);
#endif

/*
 * Get I/O statistics for a block device handle.
 * All output pointers are optional (pass NULL to skip).
 */
void mxfs_pal_bdev_get_write_stats(mxfs_bdev_t *dev,
                                    uint64_t *writes, uint64_t *write_bytes,
                                    uint64_t *writes_fua, uint64_t *write_fua_bytes,
                                    uint64_t *flushes);

/* ─── Memory ─── */

/*
 * Allocate size bytes of zeroed memory.
 * Returns NULL on failure.
 */
void *mxfs_pal_alloc(size_t size);

/*
 * Free memory previously allocated by mxfs_pal_alloc.
 */
void mxfs_pal_free(void *ptr);

/*
 * Reallocate memory to a new size.
 * Returns NULL on failure (original ptr is still valid).
 */
void *mxfs_pal_realloc(void *ptr, size_t new_size);

/* ─── Threading ─── */

/*
 * Create and start a new thread.
 * Returns NULL on failure.
 */
mxfs_thread_t *mxfs_pal_thread_create(void (*fn)(void *), void *arg);

/*
 * Create and start a new thread with real-time (low) priority.
 * On Linux kernel, uses sched_set_fifo_low() to give the thread
 * SCHED_FIFO at the lowest RT priority.  This prevents starvation
 * by CFS tasks (e.g. iSCSI completions, block I/O softirqs).
 * Use for time-critical threads like lease renewal/monitor.
 * Returns NULL on failure.
 */
mxfs_thread_t *mxfs_pal_thread_create_rt(void (*fn)(void *), void *arg);

/*
 * Wait for a thread to finish and free its resources.
 */
void mxfs_pal_thread_join(mxfs_thread_t *t);

/*
 * Wait for a thread to finish with a timeout (milliseconds).
 * Returns 0 on success (thread exited), -ETIMEDOUT if the thread
 * did not exit within timeout_ms.  On timeout the thread is NOT
 * freed — caller must handle the abandoned thread.
 */
int mxfs_pal_thread_join_timeout(mxfs_thread_t *t, uint32_t timeout_ms);

/*
 * OS task id of a PAL thread, for diagnostics that name or inspect the
 * task (mxfs_pal_dump_task_stack).  0 when unavailable (user mode).
 */
int mxfs_pal_thread_pid(mxfs_thread_t *t);

/* ─── Mutex ─── */

/*
 * Create a new mutex.
 * Returns NULL on failure.
 */
mxfs_mutex_t *mxfs_pal_mutex_create(void);

/*
 * Destroy a mutex.
 */
void mxfs_pal_mutex_destroy(mxfs_mutex_t *m);

/*
 * Lock a mutex (blocking).
 */
void mxfs_pal_mutex_lock(mxfs_mutex_t *m);

/*
 * Unlock a mutex.
 */
void mxfs_pal_mutex_unlock(mxfs_mutex_t *m);

/* ─── Spinlock ───
 *
 * interactive session 2026-07-13: NEVER sleeps, unlike mxfs_mutex_t — safe
 * to acquire while already holding another spinlock (e.g. a kernel caller's
 * own spinlock_t) or otherwise in a context that must not schedule.  In the
 * kernel PAL this wraps a real spinlock_t; in the user PAL a plain mutex is
 * fine (user-mode has no atomic-context restriction, and nothing in this
 * tree spin-waits on it across a real blocking call).
 */

/*
 * Create a new spinlock.
 * Returns NULL on failure.
 */
mxfs_spinlock_t *mxfs_pal_spinlock_create(void);

/*
 * Destroy a spinlock.
 */
void mxfs_pal_spinlock_destroy(mxfs_spinlock_t *s);

/*
 * Lock a spinlock (blocking, must not sleep across it).
 */
void mxfs_pal_spinlock_lock(mxfs_spinlock_t *s);

/*
 * Unlock a spinlock.
 */
void mxfs_pal_spinlock_unlock(mxfs_spinlock_t *s);

/* ─── Read-Write Lock ─── */

/*
 * Create a new read-write lock.
 * Returns NULL on failure.
 */
mxfs_rwlock_t *mxfs_pal_rwlock_create(void);

/*
 * Destroy a read-write lock.
 */
void mxfs_pal_rwlock_destroy(mxfs_rwlock_t *rw);

/*
 * Acquire read lock (shared, multiple readers allowed).
 */
void mxfs_pal_rwlock_rdlock(mxfs_rwlock_t *rw);

/*
 * Try to acquire the read lock WITHOUT EVER SLEEPING.  Returns 1 if the
 * lock was taken (caller must mxfs_pal_rwlock_unlock), 0 if it was not.
 *
 * ccloop c7ee71c6 sess21: this exists because mxfs_rwlock_t is a SLEEPING
 * lock in the kernel PAL (struct rw_semaphore), so mxfs_pal_rwlock_rdlock
 * is illegal in atomic context — see mxfs_dlm_held_mode_nb.  Only the
 * trylock form is safe to call with a spinlock held.
 */
int mxfs_pal_rwlock_tryrdlock(mxfs_rwlock_t *rw);

/*
 * Is the current context allowed to sleep?  1 = yes, 0 = atomic (spinlock
 * held, preemption or IRQs disabled).  User-mode builds always return 1.
 *
 * ccloop c7ee71c6 sess21: exists so the DLM layer can ASSERT its sleeping
 * entry points are not reached from atomic context, without importing a
 * kernel API outside pal/ (architectural invariant 4).  Sleeping under
 * pag_ici_lock corrupts preempt state and soft-locks a peer CPU forever,
 * and that bug reached the tree TWICE (sess19 via a SCSI read, sess20 via
 * an rwsem) because nothing checked.
 */
int mxfs_pal_may_sleep(void);

/*
 * Acquire write lock (exclusive).
 */
void mxfs_pal_rwlock_wrlock(mxfs_rwlock_t *rw);

/*
 * Release read or write lock.
 */
void mxfs_pal_rwlock_unlock(mxfs_rwlock_t *rw);

/* ─── Condition Variable ─── */

/*
 * Create a new condition variable.
 * Returns NULL on failure.
 */
mxfs_cond_t *mxfs_pal_cond_create(void);

/*
 * Destroy a condition variable.
 */
void mxfs_pal_cond_destroy(mxfs_cond_t *c);

/*
 * Wait on a condition variable with a mutex held.
 * The mutex is released during the wait and re-acquired before return.
 */
void mxfs_pal_cond_wait(mxfs_cond_t *c, mxfs_mutex_t *m);

/*
 * Wait on a condition variable with a timeout.
 * Returns 0 if signaled, -ETIMEDOUT if timeout expired.
 */
int mxfs_pal_cond_timedwait(mxfs_cond_t *c, mxfs_mutex_t *m,
                            uint64_t timeout_ms);

/*
 * Signal one waiter on a condition variable.
 */
void mxfs_pal_cond_signal(mxfs_cond_t *c);

/*
 * Signal all waiters on a condition variable.
 */
void mxfs_pal_cond_broadcast(mxfs_cond_t *c);

/* ─── TCP Networking ─── */

/*
 * Create a TCP connection to host:port.
 * Returns NULL on failure.
 */
mxfs_sock_t *mxfs_pal_tcp_connect(const char *host, uint16_t port);

/*
 * Create a TCP listen socket on the given port.
 * Returns NULL on failure.
 */
mxfs_sock_t *mxfs_pal_tcp_listen(uint16_t port);

/*
 * Accept an incoming TCP connection.
 * Blocks until a connection arrives or the socket is closed.
 * Returns NULL on failure/shutdown.
 */
mxfs_sock_t *mxfs_pal_tcp_accept(mxfs_sock_t *listener);

/*
 * Send exactly len bytes over a TCP connection.
 * Returns 0 on success, negative errno on failure.
 */
int mxfs_pal_tcp_send(mxfs_sock_t *s, const void *buf, uint32_t len);

/*
 * Receive exactly len bytes from a TCP connection.
 * Blocks until all bytes are received, or error/EOF.
 * Returns 0 on success, negative errno on failure.
 */
int mxfs_pal_tcp_recv(mxfs_sock_t *s, void *buf, uint32_t len);

/*
 * Set TCP_NODELAY and SO_KEEPALIVE on a TCP socket.
 */
void mxfs_pal_tcp_set_opts(mxfs_sock_t *s);

/*
 * Get the remote peer's IPv4 address from an accepted TCP socket.
 * Writes a null-terminated dotted-quad string (e.g. "192.168.1.5")
 * into buf, up to buf_len bytes.
 * Returns 0 on success, negative errno on failure.
 */
int mxfs_pal_tcp_getpeername(mxfs_sock_t *s, char *buf, size_t buf_len);

/*
 * Shut down a TCP socket for read+write (SHUT_RDWR) without closing it.
 * Unblocks any blocked recv/send calls. The socket must still be closed
 * later with mxfs_pal_tcp_close().
 */
void mxfs_pal_tcp_shutdown(mxfs_sock_t *s);

/*
 * Shut down and close a TCP socket.
 */
void mxfs_pal_tcp_close(mxfs_sock_t *s);

/* ─── UDP Networking ─── */

/*
 * Create and bind a UDP socket on the given port.
 * Returns NULL on failure.
 */
mxfs_sock_t *mxfs_pal_udp_open(uint16_t port);

/*
 * Shut down a UDP socket for read+write without closing it.
 * Unblocks any blocked recvfrom/sendto calls. The socket must
 * still be closed later with mxfs_pal_udp_close().
 */
void mxfs_pal_udp_shutdown(mxfs_sock_t *s);

/*
 * Close a UDP socket.
 */
void mxfs_pal_udp_close(mxfs_sock_t *s);

/*
 * Send a UDP datagram to host:port.
 * Returns 0 on success, negative errno on failure.
 */
int mxfs_pal_udp_sendto(mxfs_sock_t *s, const void *buf, uint32_t len,
                        const char *host, uint16_t port);

/*
 * Receive a UDP datagram.
 * Fills from_host (null-terminated IP string) and from_port.
 * Returns bytes received (>0), or negative errno on failure.
 * Returns -ETIMEDOUT if receive timeout expires.
 */
int mxfs_pal_udp_recvfrom(mxfs_sock_t *s, void *buf, uint32_t len,
                          char *from_host, size_t host_len,
                          uint16_t *from_port);

/*
 * Join a multicast group.
 * Returns 0 on success, negative errno on failure.
 */
int mxfs_pal_udp_join_multicast(mxfs_sock_t *s, const char *group);

/*
 * Enable SO_BROADCAST on a UDP socket.
 * Returns 0 on success, negative errno on failure.
 */
int mxfs_pal_udp_set_broadcast(mxfs_sock_t *s);

/*
 * Set receive timeout on a UDP socket.
 * Returns 0 on success, negative errno on failure.
 */
int mxfs_pal_udp_set_recv_timeout(mxfs_sock_t *s, uint32_t timeout_ms);

/* ─── Time ─── */

/*
 * Get monotonic time in milliseconds (since boot).
 * Use for internal timers, lease timeouts, etc.
 */
uint64_t mxfs_pal_time_ms(void);

/*
 * Get real (wall-clock) time in seconds since Unix epoch.
 * Use for file timestamps (atime, mtime, ctime).
 */
uint64_t mxfs_pal_time_real_sec(void);

/*
 * Get real (wall-clock) time in milliseconds since Unix epoch.
 * fence_during_write@8caw livelock fix: mxfs_pal_time_ms() is boot-relative
 * (ktime_get_boottime_ns() in-kernel) -- each node's clock starts at 0 from
 * ITS OWN boot, so it is NOT comparable across nodes.  A value written by one
 * node and read/subtracted by another (e.g. dlm/dlm_caw.c's CAW fair-handoff
 * yield_to/yield_set_ms staleness ticket) silently underflows as unsigned
 * arithmetic whenever the reading node has less boot-uptime than the writing
 * node, making a fresh ticket look instantly stale.  PROVEN (live dmesg,
 * 8-node cluster with independently power-cycled nodes): P-YT-STALECLR fired
 * 83-251x/node during a single ~360s starvation window -- the round-robin
 * anti-starvation ticket was being cleared as "stale" almost immediately,
 * every time, defeating the mechanism.  Use this for ANY timestamp that one
 * node writes and a DIFFERENT node later reads/ages; keep mxfs_pal_time_ms()
 * for single-node-local timers (backoff, lease-hold duration on the SAME
 * node measuring its OWN elapsed time).
 */
uint64_t mxfs_pal_time_real_ms(void);

/*
 * Sleep for the given number of milliseconds.
 */
void mxfs_pal_sleep_ms(uint32_t ms);

/*
 * Sleep INTERRUPTIBLY.
 *
 * sess381: mxfs_pal_sleep_ms() is msleep(), which is TASK_UNINTERRUPTIBLE, so a
 * long-lived kernel thread that idles in it shows as a permanent D-state task —
 * +1 to loadavg per such thread, forever, on every mounted node, and
 * indistinguishable from the wedged-in-I/O tasks the rig's readiness check
 * exists to catch.  It was caught by precond_readiness the first time an
 * always-on background worker used it ("no D-state mxfs/writeback task ...
 * mxfs-worker[msleep]").
 *
 * Use this for any background worker's idle wait; keep mxfs_pal_sleep_ms() for
 * short in-operation backoffs where the D window is bounded and meaningful.
 */
void mxfs_pal_sleep_ms_interruptible(uint32_t ms);

/*
 * Conditionally reschedule to prevent soft lockups.
 * In kernel context, calls cond_resched() to yield the CPU if
 * the scheduler needs to run other tasks. In userspace, this is
 * a no-op (userspace threads are preemptible).
 * Call periodically in long-running loops (e.g. bulk I/O).
 */
void mxfs_pal_cond_resched(void);

/* ─── Logging ─── */

/*
 * Log a message at the given level.
 * Uses printf-style format string.
 */
#ifdef __KERNEL__
__printf(2, 3)
#else
__attribute__((format(printf, 2, 3)))
#endif
void mxfs_pal_log(int level, const char *fmt, ...);

/*
 * Dump the calling thread's kernel stack to the log (kernel: dump_stack();
 * user builds: no-op).  Diagnostic only — used by capped one-shot probes
 * that need the wait-site call chain (e.g. the P36 acquire-timeout ABBA
 * forensics).
 */
void mxfs_pal_dump_stack(void);
void mxfs_pal_dump_task_stack(int pid);	/* dump another task's kernel stack by pid (0 = no-op) */

/* ─── Fail-stop ─── */

/*
 * sess133 (GPT sess133 ruling B1): NON-RETURNING LOCAL FAIL-STOP.
 *
 * The clustered-filesystem answer to "this node can neither prove it released
 * its shared-storage state nor safely continue".  It exists because the two
 * alternatives were both rejected on evidence:
 *
 *   waiting forever   — blocks unmount and module unload permanently, and the
 *                       uninterruptible LUN I/O that caused it never observes
 *                       cancellation;
 *   abandon and leak  — returning to put_super with the BAST threads still
 *                       live is a USE-AFTER-FREE: those threads call back
 *                       through closures that hold the XFS mount, and the VFS
 *                       frees that mount regardless of anything the DLM
 *                       decides.  Leaking the DLM contexts does not save it.
 *
 * So the node stops touching shared storage the only way it provably can.
 * Peers detect the silence through the ordinary dead-node path and fence,
 * replay and purge it — which is exactly what a departure that could not be
 * proven clean requires of them anyway.
 *
 * It NEVER returns, and it must never be reachable in normal operation: every
 * caller reaches it only after a deadline derived to exceed every deadline the
 * DLM itself imposes has expired, plus a further bounded grace.
 *
 * Kernel: panic().  User builds: abort() (the tools have no shared-storage
 * state to protect, but must not continue past a failed invariant either).
 *
 * ─── sess134: WHY THIS IS A MACRO OVER A NON-__noreturn FUNCTION ───
 *
 * objtool validates control flow per object file against a HARDCODED list of
 * noreturn functions and cannot learn about one defined in another translation
 * unit.  Marked __noreturn, GCC correctly emits no return instruction after a
 * call, and objtool then reports every caller as falling through into whatever
 * symbol the linker placed next — a warning on a build that must stay clean.
 * `unreachable()` does not suppress it (the annotate_unreachable machinery it
 * carried is gone), and neither does moving the call off the function tail: GCC
 * sinks the cold branch back to the end anyway.
 *
 * So the attribute is dropped and the macro supplies its own terminator.  The
 * spin is not decoration: it is what makes "never returns" true at the call
 * site regardless of what the implementation does, and objtool accepts an
 * unconditional self-branch as a valid end of flow.  A node that somehow
 * returned from panic() spinning here is still a node that has stopped issuing
 * I/O to the shared LUN, which is the entire guarantee this call exists to
 * provide.
 */
#ifdef __KERNEL__
__printf(1, 2)
#else
__attribute__((format(printf, 1, 2)))
#endif
void mxfs_pal_failstop_fn(const char *fmt, ...);

#define mxfs_pal_failstop(fmt, ...)                            \
	do {                                                   \
		mxfs_pal_failstop_fn((fmt), ##__VA_ARGS__);    \
		for (;;)                                       \
			mxfs_pal_cond_resched();               \
	} while (0)

/* ─── Deferred one-shot call ─── */

/*
 * sess133 (GPT sess133 ruling B3): run fn(arg) SOON, in a context that is not
 * the caller's, exactly once.
 *
 * The escalation notifier needs this.  Delivering an upcall from inside
 * teardown's own quiesce loop makes the lower layer's liveness depend on the
 * upper layer's handler: a handler that blocks, re-enters, or takes a lock the
 * caller holds wedges the very loop that is trying to shut the mount down, and
 * one that re-enters stop() would wait for the thread it is running on.
 *
 * Returns 0 when the call is queued, negative when it could not be (the caller
 * must then treat the notification as undelivered — it is a channel, never a
 * latch).  Kernel: a system unbound workqueue item, so a blocked handler
 * cannot starve other work.  User: a detached thread.
 *
 * fn owns nothing: the caller must keep `arg` alive until fn has run, which is
 * the caller's problem and not this primitive's.
 */
int mxfs_pal_defer(void (*fn)(void *), void *arg);

/* ─── CRC32C ─── */

/*
 * Compute CRC32C (Castagnoli) checksum.
 * Used for XFS v5 metadata CRC verification.
 * crc is the initial seed value (typically ~0U for new checksums).
 */
uint32_t mxfs_pal_crc32c(uint32_t crc, const void *data, size_t len);

/* ─── Sorting ─── */

/*
 * Sort an array in-place using the provided comparison function.
 * comp(a, b) returns <0 if a<b, 0 if a==b, >0 if a>b.
 */
void mxfs_pal_sort(void *base, size_t nmemb, size_t size,
                   int (*comp)(const void *, const void *));

/* ─── SCSI PR (Persistent Reservations) ───
 *
 * Optional — for hardware fencing. Platforms that don't support
 * SCSI PR return -EOPNOTSUPP from all functions.
 */

/*
 * Register this node's key with the device.
 * Uses REGISTER_AND_IGNORE for idempotent re-registration.
 * Returns 0 on success, negative errno on failure.
 */
int mxfs_pal_scsi_pr_register(mxfs_bdev_t *dev, uint64_t key);

/*
 * Acquire a persistent reservation of `type` (an MXFS_PAL_PR_TYPE_* wire
 * value; only WR_EX_RO and WR_EX_AR are accepted).
 *
 * sess381 (D-PR-RESERVATION-SINGLE-HOLDER-UNMOUNT-DISARMS-FENCING-381):
 * this used to hardcode WR_EX_RO and to SWALLOW a RESERVATION CONFLICT into
 * 0 ("we're registered, which is all we need for type 5 access").  Both were
 * wrong.  WR_EX_RO is a SINGLE-HOLDER type: SPC releases it when its holder's
 * registration is removed, so the holder's routine clean unmount disarmed
 * fencing for the WHOLE cluster (measured: one 0.49s umount took the LUN from
 * a held reservation to none, with 31 nodes still mounted, and the next peer
 * death was unfenceable).  Under WR_EX_AR every registrant is a holder, so
 * the reservation survives until the last registration goes.
 *
 * Return convention — a caller may NOT collapse these:
 *   0        the reservation of `type` is now in force for this initiator.
 *   -EBUSY   RESERVATION CONFLICT.  Under an all-registrants type this is
 *            ABNORMAL for a registered requester (SPC completes a matching
 *            scope+type RESERVE from a holder with GOOD, and every registrant
 *            is a holder) — it means the existing reservation has a different
 *            type or scope, or our registration is gone.  The caller must
 *            read back and classify, never treat it as success.
 *   <0 other transport/target failure; the reservation state is UNKNOWN and
 *            must not be assumed established.
 */
int mxfs_pal_scsi_pr_reserve(mxfs_bdev_t *dev, uint64_t key, uint32_t type);

/*
 * Preempt a dead node's key.
 *
 * abort=false issues SPC PREEMPT (service action 0x04): the victim's
 * registration is removed, so commands the target has not yet BEGUN
 * PROCESSING are rejected with RESERVATION CONFLICT — but the victim's
 * already-started task set is NOT aborted and may still reach the platter.
 * abort=true issues PREEMPT AND ABORT (0x05), which additionally aborts
 * that task set and does not complete until it is aborted.
 *
 * For I/O fencing the caller MUST pass abort=true: MXFS kills victims
 * mid-write, so the in-flight window is exactly the window that matters
 * (sess71, D-PR-FENCE-PREEMPT-WITHOUT-ABORT).
 *
 * Return convention — a caller may NOT collapse these:
 *   0        the service action was accepted and COMPLETED by the target.
 *            With abort=true this is the only value that proves the
 *            victim's task set was aborted.
 *   -EBUSY   RESERVATION CONFLICT.  Our command performed NOTHING: the
 *            SARK was not a registered key (another initiator preempted
 *            it first, or it was never registered).  This is NOT success —
 *            it proves only that the key is absent NOW, which says nothing
 *            about whether anyone ever aborted the victim's task set.
 *   <0 other transport/target failure; outcome unknown.
 */
int mxfs_pal_scsi_pr_preempt(mxfs_bdev_t *dev, uint64_t my_key,
                             uint64_t victim_key, bool abort, uint32_t type);

/*
 * Unregister this node's key on clean shutdown.
 * Returns 0 on success, negative errno on failure.
 */
int mxfs_pal_scsi_pr_unregister(mxfs_bdev_t *dev, uint64_t key);

/*
 * Read all currently registered keys.
 * Returns 0 on success, negative errno on failure.
 * *count is set to the number of keys written to keys[].
 *
 * generation (optional, may be NULL) receives the PR GENERATION counter
 * the target reported with this read.  It increments on every PR OUT that
 * changes the registrations, so it dates a key-set observation: evidence
 * recorded against one generation is known stale once it differs.
 *
 * total (optional, may be NULL) receives the number of registration
 * descriptors the TARGET reports holding, which may exceed max_keys.  This
 * is the only way to tell a complete view from a truncated one, and the
 * distinction is load-bearing: every MXFS consumer of this table decides
 * from key ABSENCE ("our key is gone" ⇒ we were preempted ⇒ self-fence;
 * "the victim's key is gone" ⇒ someone else fenced it), and truncation
 * manufactures absence.  A caller that classifies without comparing
 * *count against *total will eventually freeze a healthy node because its
 * key fell off the end of the buffer.  Registrations are per-I_T nexus,
 * NOT per node — a multipath node holds one descriptor per path — so a
 * buffer sized by node count is not big enough.
 */
int mxfs_pal_scsi_pr_read_keys(mxfs_bdev_t *dev, uint64_t *keys,
                               int max_keys, int *count,
                               uint32_t *generation, int *total);

/*
 * PERSISTENT RESERVE IN / READ FULL STATUS (service action 0x03).
 *
 * Ask the TARGET whether a registration descriptor carrying `key` exists
 * right now.  This is the only authoritative "am I still registered?"
 * probe available to a possibly-fenced node: PR IN is permitted to an
 * unregistered initiator under WE-RO, and the answer is generated by the
 * target at command time — unlike a media read of the heartbeat sector,
 * which can be arbitrarily stale on a wedged initiator (sess276: the
 * fenced victim's reads were 51 generations behind the platter).
 *
 * *present  ← 1 if `key` is registered, 0 if provably absent.
 * *generation (optional) ← PR GENERATION at the time of the read.
 *
 * Returns 0 only when the question was answered.  -EOPNOTSUPP when the
 * platform or target cannot answer it (caller falls back to READ KEYS);
 * -EPROTO on a response parse anomaly.  On ANY nonzero return *present
 * is meaningless and MUST NOT be read as absence.
 */
int mxfs_pal_scsi_pr_read_full_status(mxfs_bdev_t *dev, uint64_t key,
                                      int *present, uint32_t *generation);

/* SPC persistent-reservation type codes MXFS cares about (WIRE values). */
#define MXFS_PAL_PR_TYPE_WR_EX_RO   0x05    /* Write Exclusive - Registrants Only */
#define MXFS_PAL_PR_TYPE_WR_EX_AR   0x07    /* Write Exclusive - All Registrants */

/*
 * A reservation as reported by PERSISTENT RESERVE IN / READ RESERVATION.
 *
 * `held` is the discriminator: when false the LUN has NO reservation and
 * `key`/`type` are meaningless.  That distinction is load-bearing — with no
 * reservation held, an unregistered initiator may write freely, so the
 * absence of a victim's key proves nothing at all about exclusion.
 */
struct mxfs_pal_pr_reservation {
    /*
     * The holder's key — MEANINGFUL ONLY FOR SINGLE-HOLDER TYPES.  Under an
     * all-registrants type there is no single holder and SPC reports this
     * field as ZERO (measured on SCST: READ RESERVATION returns Key=0x0 for
     * a WR_EX_AR reservation).  `held` is therefore decided by `type`, never
     * by this field — the pre-sess381 `held = (key != 0)` test would have
     * reported a live WR_EX_AR reservation as "none held".
     */
    uint64_t    key;            /* reservation-holder's key (0 under *_AR) */
    uint32_t    generation;     /* PR GENERATION at the time of the read */
    uint32_t    type;           /* SPC PR type (MXFS_PAL_PR_TYPE_*) */
    bool        held;           /* a reservation is currently held */
};

/*
 * Read the currently held reservation.
 * Returns 0 on success (including "none held" — see ->held), negative
 * errno on failure, -EOPNOTSUPP where the platform cannot report it.
 */
int mxfs_pal_scsi_pr_read_reservation(mxfs_bdev_t *dev,
                                      struct mxfs_pal_pr_reservation *out);

/*
 * PERSISTENT RESERVE IN / REPORT CAPABILITIES (service action 0x02).
 *
 * The single command that answers, AT MOUNT TIME, whether this device can
 * actually produce the fencing evidence recovery will later demand.  Before
 * sess378 MXFS never issued it, so the first time anyone learned that PR was
 * absent, that persistence was not active, or that WR_EX_RO was not offered,
 * was AFTER a peer had died — by which point the slice is unrecoverable and
 * peers are already blocked on its grants.
 *
 * `abort_capable` is NOT part of the SCSI response.  It is the platform's
 * answer to "can a genuine PREEMPT AND ABORT (SA 0x05) be issued on this
 * device at all", which on Linux is a separate question from whether the
 * target supports it: dm_pr_preempt() drops the abort flag, so MXFS issues
 * the raw CDB itself and that requires an underlying scsi_device to exist.
 * A device with abort_capable == false can register, reserve and preempt, and
 * will still silently fail to abort a victim's in-flight writes.
 */
struct mxfs_pal_pr_caps {
    uint16_t    type_mask;      /* raw PERSISTENT RESERVATION TYPE MASK */
    bool        ptpl_c;         /* persist-through-power-loss CAPABLE */
    bool        ptpl_a;         /* persist-through-power-loss ACTIVATED */
    bool        crh;            /* compatible reservation handling */
    bool        sip_c;          /* specify-initiator-ports capable */
    bool        atp_c;          /* all-target-ports capable */
    bool        tmv;            /* TYPE MASK VALID */
    bool        we_ro;          /* WR_EX_RO (type 5) offered by the mask */
    bool        we_ar;          /* WR_EX_AR (type 7) offered by the mask —
                                 * the type MXFS reserves under proto-gen 5+;
                                 * see mxfs_pal_scsi_pr_reserve() */
    bool        abort_capable;  /* a real SA 0x05 can be issued (see above) */
};

/*
 * Returns 0 and fills *out on success; -EOPNOTSUPP where the target or the
 * platform cannot report capabilities; negative errno otherwise.
 */
int mxfs_pal_scsi_pr_report_capabilities(mxfs_bdev_t *dev,
                                         struct mxfs_pal_pr_caps *out);

/* ─── SCSI COMPARE AND WRITE ───
 *
 * Atomic compare-and-swap at sector granularity.
 * Used for lock-free coordination on shared block devices.
 */

/*
 * SCSI COMPARE AND WRITE — atomic compare-and-swap at sector granularity.
 * Reads sector at offset, compares against compare_buf (512 bytes).
 * If match, atomically writes write_buf (512 bytes).
 *
 * Returns:
 *   0         — success (compare matched, write completed)
 *   -EAGAIN   — MISCOMPARE (another node modified the sector; caller should retry)
 *   -EIO      — I/O error
 *   -EOPNOTSUPP — device does not support COMPARE AND WRITE
 */
int mxfs_pal_bdev_compare_and_write(mxfs_bdev_t *dev, uint64_t offset,
                                     const void *compare_buf,
                                     const void *write_buf);

/*
 * Drop the cached backing-path (scsi_device) references held for stacked
 * devices (dm-multipath) — call once at module exit.  No-op in user mode.
 */
void mxfs_pal_sdev_cache_release(void);

/* ─── Page cache support (kernel only) ─── */

#ifdef __KERNEL__
#include <linux/blkdev.h>
#include <linux/sched.h>
#include <linux/list.h>

/*
 * Get the underlying struct block_device for page cache I/O.
 * Returns NULL if dev is NULL.
 */
struct block_device *mxfs_pal_bdev_get_bdev(mxfs_bdev_t *dev);

/*
 * Get the base offset added to all I/O through this device.
 * Returns 0 if dev is NULL.
 */
uint64_t mxfs_pal_bdev_get_base_offset(mxfs_bdev_t *dev);

/* ─── Per-task absolute I/O budget (kernel only) ─── */

/*
 * sess379 (D-MASS-UMOUNT-ROOT-EX-SERIALIZE-100S-526B, RULE-5 ruling item 5).
 *
 * Puts ONE absolute deadline on every SCSI slot read this task issues for the
 * span of one logical operation, replacing the stacked
 * `30 s command timeout x 1 SCSI retry x 20 wrapper retries` (~20 minutes for
 * a single slot probe) with a bound the caller chose.  Attempt budgets are
 * capped by the time remaining; when it is gone the read returns -ETIME and
 * logs P302-FUA-READ-DEADLINE.
 *
 * -ETIME means NO SAMPLE.  It is never evidence that a lock is held, is not
 * held, or that the device is healthy — a caller that treats it as any of
 * those has reintroduced the defect this exists to remove.
 *
 * Scope it to the smallest span that needs it and ALWAYS pair enter/exit on
 * the same stack frame; the registration is keyed on `current` and a leaked
 * entry would silently bound every later read that task issues, including
 * authoritative ones.  Do NOT put a budget on an authoritative read whose
 * failure escalates: converting a transient target stall into -EIO is how a
 * healthy node manufactures a shutdown
 * (D-UMOUNT-QUARANTINE-TIMEOUT-DIRTY-WITHDRAW-356).
 */
struct mxfs_pal_io_budget {
	struct task_struct	*task;
	unsigned long		deadline_j;
	struct hlist_node	node;
};

void mxfs_pal_io_budget_enter(struct mxfs_pal_io_budget *b, uint32_t ms);
void mxfs_pal_io_budget_exit(struct mxfs_pal_io_budget *b);
#endif

/* ─── Hostname ─── */

/*
 * Get the local hostname.
 * Writes up to len bytes (including null terminator) into buf.
 * Returns 0 on success.
 */
int mxfs_pal_get_hostname(char *buf, size_t len);

/* ─── File I/O ─── */

/*
 * Read a small file into a caller-provided buffer.
 * Reads up to buf_size bytes from the file at path.
 * Returns number of bytes read on success, negative errno on failure.
 * Intended for reading config files (e.g. /etc/mxfs/node.uuid).
 */
int mxfs_pal_read_file(const char *path, void *buf, size_t buf_size);

/*
 * Fill buf with len bytes of cryptographic-quality random data.
 * Kernel: get_random_bytes(). Userspace: /dev/urandom.
 */
void mxfs_pal_get_random_bytes(void *buf, size_t len);

/* ─── Atomic operations ─── */

/*
 * Atomic 32-bit integer type and operations.
 * Used for reference counts and flags.
 */
#ifdef __KERNEL__

#include <linux/atomic.h>

typedef struct mxfs_atomic32 {
    atomic_t val;
} mxfs_atomic32_t;

static inline void mxfs_atomic32_set(mxfs_atomic32_t *a, int32_t v)
{
    atomic_set(&a->val, v);
}

static inline int32_t mxfs_atomic32_get(mxfs_atomic32_t *a)
{
    return atomic_read(&a->val);
}

static inline int32_t mxfs_atomic32_inc(mxfs_atomic32_t *a)
{
    return atomic_inc_return(&a->val);
}

static inline int32_t mxfs_atomic32_dec(mxfs_atomic32_t *a)
{
    return atomic_dec_return(&a->val);
}

#else /* userspace */

typedef struct mxfs_atomic32 {
    volatile int32_t val;
} mxfs_atomic32_t;

static inline void mxfs_atomic32_set(mxfs_atomic32_t *a, int32_t v)
{
    __atomic_store_n(&a->val, v, __ATOMIC_SEQ_CST);
}

static inline int32_t mxfs_atomic32_get(mxfs_atomic32_t *a)
{
    return __atomic_load_n(&a->val, __ATOMIC_SEQ_CST);
}

static inline int32_t mxfs_atomic32_inc(mxfs_atomic32_t *a)
{
    return __atomic_add_fetch(&a->val, 1, __ATOMIC_SEQ_CST);
}

static inline int32_t mxfs_atomic32_dec(mxfs_atomic32_t *a)
{
    return __atomic_sub_fetch(&a->val, 1, __ATOMIC_SEQ_CST);
}

#endif /* __KERNEL__ */

/* ─── Byte order helpers ─── */

/*
 * Convert between big-endian (on-disk XFS format) and host byte order.
 * Byte swapping is symmetric: swap(swap(x)) == x, so the same function
 * works for both directions (be->cpu and cpu->be).
 */

#ifdef __KERNEL__

/* Kernel has its own endian conversion macros */
#include <asm/byteorder.h>

static inline uint16_t mxfs_be16_to_cpu(uint16_t v) {
    return be16_to_cpu((__force __be16)v);
}
static inline uint32_t mxfs_be32_to_cpu(uint32_t v) {
    return be32_to_cpu((__force __be32)v);
}
static inline uint64_t mxfs_be64_to_cpu(uint64_t v) {
    return be64_to_cpu((__force __be64)v);
}
static inline uint16_t mxfs_le16_to_cpu(uint16_t v) {
    return le16_to_cpu((__force __le16)v);
}
static inline uint32_t mxfs_le32_to_cpu(uint32_t v) {
    return le32_to_cpu((__force __le32)v);
}
static inline uint64_t mxfs_le64_to_cpu(uint64_t v) {
    return le64_to_cpu((__force __le64)v);
}

#elif defined(_WIN32)

/* Windows is always little-endian on x86/x64/ARM */
static inline uint16_t mxfs_be16_to_cpu(uint16_t v) {
    return (uint16_t)((v >> 8) | (v << 8));
}
static inline uint32_t mxfs_be32_to_cpu(uint32_t v) {
    return ((v >> 24) & 0xFFU) | ((v >> 8) & 0xFF00U) |
           ((v << 8) & 0xFF0000U) | ((v << 24) & 0xFF000000U);
}
static inline uint64_t mxfs_be64_to_cpu(uint64_t v) {
    return ((uint64_t)mxfs_be32_to_cpu((uint32_t)v) << 32) |
           mxfs_be32_to_cpu((uint32_t)(v >> 32));
}
static inline uint16_t mxfs_le16_to_cpu(uint16_t v) { return v; }
static inline uint32_t mxfs_le32_to_cpu(uint32_t v) { return v; }
static inline uint64_t mxfs_le64_to_cpu(uint64_t v) { return v; }

#else /* Linux userspace, macOS, other POSIX */

#include <endian.h>
#include <byteswap.h>

static inline uint16_t mxfs_be16_to_cpu(uint16_t v) {
#if __BYTE_ORDER == __BIG_ENDIAN
    return v;
#else
    return bswap_16(v);
#endif
}
static inline uint32_t mxfs_be32_to_cpu(uint32_t v) {
#if __BYTE_ORDER == __BIG_ENDIAN
    return v;
#else
    return bswap_32(v);
#endif
}
static inline uint64_t mxfs_be64_to_cpu(uint64_t v) {
#if __BYTE_ORDER == __BIG_ENDIAN
    return v;
#else
    return bswap_64(v);
#endif
}
static inline uint16_t mxfs_le16_to_cpu(uint16_t v) {
#if __BYTE_ORDER == __BIG_ENDIAN
    return bswap_16(v);
#else
    return v;
#endif
}
static inline uint32_t mxfs_le32_to_cpu(uint32_t v) {
#if __BYTE_ORDER == __BIG_ENDIAN
    return bswap_32(v);
#else
    return v;
#endif
}
static inline uint64_t mxfs_le64_to_cpu(uint64_t v) {
#if __BYTE_ORDER == __BIG_ENDIAN
    return bswap_64(v);
#else
    return v;
#endif
}

#endif /* __KERNEL__ / _WIN32 / POSIX */

/* Symmetric: cpu-to-disk is same as disk-to-cpu */
#define mxfs_cpu_to_be16 mxfs_be16_to_cpu
#define mxfs_cpu_to_be32 mxfs_be32_to_cpu
#define mxfs_cpu_to_be64 mxfs_be64_to_cpu
#define mxfs_cpu_to_le16 mxfs_le16_to_cpu
#define mxfs_cpu_to_le32 mxfs_le32_to_cpu
#define mxfs_cpu_to_le64 mxfs_le64_to_cpu

#endif /* MXFS_PAL_H */

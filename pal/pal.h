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
 * Acquire WRITE EXCLUSIVE - REGISTRANTS ONLY reservation.
 * Returns 0 on success (including if another node holds the reservation,
 * since all registered nodes can do I/O with type 5).
 */
int mxfs_pal_scsi_pr_reserve(mxfs_bdev_t *dev, uint64_t key);

/*
 * Preempt a dead node's key — atomically removes victim and
 * transfers reservation to us.
 * Returns 0 on success, negative errno on failure.
 */
int mxfs_pal_scsi_pr_preempt(mxfs_bdev_t *dev, uint64_t my_key,
                             uint64_t victim_key);

/*
 * Unregister this node's key on clean shutdown.
 * Returns 0 on success, negative errno on failure.
 */
int mxfs_pal_scsi_pr_unregister(mxfs_bdev_t *dev, uint64_t key);

/*
 * Read all currently registered keys.
 * Returns 0 on success, negative errno on failure.
 * *count is set to the number of keys written to keys[].
 */
int mxfs_pal_scsi_pr_read_keys(mxfs_bdev_t *dev, uint64_t *keys,
                               int max_keys, int *count);

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

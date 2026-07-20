# PAL — Platform Abstraction Layer

## Overview

The PAL provides OS-specific primitives to libmxfs. All libmxfs code uses PAL for block I/O, threading, networking, memory, time, logging, SCSI PR, and sorting. Each platform provides its own implementation of the interface defined in `pal.h`.

## Files

- `pal.h` — Interface definition (all function declarations, opaque types, atomics, byte-order helpers)
- `pal_linux_user.c` — Linux userspace implementation (pthreads, POSIX sockets, O_DIRECT)
- `pal_linux_kern.c` — Linux kernel implementation (bio, kthread, kernel sockets)

## Architecture

### pal.h

Defines opaque types:
- `mxfs_bdev_t` — block device handle
- `mxfs_thread_t` — thread handle
- `mxfs_mutex_t` — mutex handle
- `mxfs_cond_t` — condition variable handle
- `mxfs_rwlock_t` — read-write lock handle
- `mxfs_sock_t` — socket handle (TCP or UDP)

Uses `__KERNEL__` ifdefs to support both userspace and kernel compilation:
- Includes: `linux/types.h` etc. in kernel vs `stdint.h` etc. in userspace
- Atomics: `atomic_t` in kernel vs `__atomic` builtins in userspace
- Byte order: `be32_to_cpu()` etc. in kernel vs `bswap_32()` in userspace
- Printf attribute: `__printf(2,3)` in kernel vs `__attribute__((format(...)))` in userspace

### pal_linux_kern.c (Kernel PAL)

Implements all PAL functions using kernel APIs:

| PAL Function | Kernel API |
|---|---|
| bdev_open/close | blkdev_get_by_path / bdev_open_by_path (6.8+) |
| bdev_read | pipelined: bio_alloc + submit_bio + bi_end_io callback (up to 16 concurrent) |
| bdev_read_prio | bdev_sync_io with REQ_PRIO \| REQ_SYNC (priority lane for DLM lock I/O) |
| bdev_write | bio_alloc + bio_add_page + submit_bio_wait (synchronous) |
| bdev_write_async | pipelined: bio_alloc + submit_bio + bi_end_io callback (up to 16 concurrent) |
| bdev_read_async | pipelined: bio_alloc + submit_bio + bi_end_io callback (up to 16 concurrent) |
| bdev_flush | blkdev_issue_flush |
| bdev_write_gather | bio_alloc (multi-page) + submit_bio_wait |
| alloc/free | kzalloc/vzalloc + kvfree |
| realloc | krealloc (vmalloc-safe fallback) |
| thread_create/join | kthread_create + completion |
| thread_create_rt | kthread_create + sched_set_fifo_low (RT prio) |
| mutex | struct mutex |
| rwlock | struct rw_semaphore (with write_held tracking) |
| cond_wait/signal | wait_queue_head_t + generation counter |
| tcp_connect/listen/accept | sock_create_kern + kernel_connect/bind/listen/accept |
| tcp_send/recv | kernel_sendmsg / kernel_recvmsg |
| tcp_set_opts | sk_rcvbuf/sk_sndbuf (4MB) + tcp_sock_set_nodelay / sock_set_keepalive / keepidle/intvl/cnt + TCP_USER_TIMEOUT via inet_csk (5.7+) |
| udp_open/sendto/recvfrom | sock_create_kern(SOCK_DGRAM) + kernel_sendmsg/recvmsg |
| udp_shutdown | kernel_sock_shutdown(SHUT_RDWR) + sk_err/sk_error_report |
| udp_join_multicast | ip_mc_join_group (5.8+) or kernel_setsockopt |
| time_ms | ktime_get_boottime_ns() / 1000000 (monotonic) |
| time_real_sec | ktime_get_real_seconds() (wall clock) |
| sleep_ms | msleep |
| crc32c | crc32c() from linux/crc32c.h |
| log | pr_debug/pr_info/pr_warn/pr_err via va_format |
| sort | sort() from linux/sort.h |
| scsi_pr_* | bd_disk->fops->pr_ops |
| bdev_compare_and_write | scsi_execute_cmd (6.3+) / scsi_execute (pre-6.3) via device model traversal |
| get_hostname | init_uts_ns.name.nodename |
| read_file | filp_open + kernel_read |
| get_random_bytes | get_random_bytes() kernel / /dev/urandom userspace |

### Kernel Compat (5.10 - 6.8+)

- Block device open: blkdev_get_by_path (pre-6.8) vs bdev_open_by_path (6.8+)
- Socket options: kernel_setsockopt (pre-5.8) vs dedicated helpers (5.8+)
- TCP options: kernel_setsockopt (pre-5.17) vs tcp_sock_set_nodelay (5.17+)

### Threading Model

The kernel PAL wraps kthreads with a completion-based join mechanism:
1. `thread_create` creates a kthread with a wrapper function
2. The wrapper signals `started` completion, runs the user function, then signals `exited` completion
3. The wrapper then loops on `kthread_should_stop()` until joined
4. `thread_join` waits for `exited` completion, then calls `kthread_stop`

### RW Lock Challenge

Linux `rw_semaphore` has separate `up_read()` and `up_write()` but the PAL has a single `rwlock_unlock()`. Solved by tracking a `write_held` flag set on `wrlock()` and cleared on `unlock()`. Safe because only one writer can hold the lock at a time.

### Condition Variable Implementation

Uses `wait_queue_head_t` with a generation counter to avoid lost wakeups:
- `cond_wait`: saves generation, prepares to wait, drops mutex, schedules if generation unchanged, re-acquires mutex
- `cond_signal`: bumps generation, wake_up (one waiter)
- `cond_broadcast`: bumps generation, wake_up_all
- `cond_timedwait`: same as wait but with schedule_timeout

## History

- Initial creation
- Added `__KERNEL__` ifdefs to pal.h for dual userspace/kernel compilation
- Kernel PAL implements all 40+ PAL functions
- 2026-02-15: Added `mxfs_pal_time_real_sec()` for wall-clock timestamps (BUG-3 fix). `mxfs_pal_time_ms()` remains monotonic for lease/timeout code. Uses `ktime_get_real_seconds()`.
- 2026-02-15: Added `mxfs_pal_crc32c()` for XFS v5 metadata CRC computation (BUG-2 fix). Wraps kernel `crc32c()` from `<linux/crc32c.h>`.
- 2026-02-16: Added `mxfs_pal_read_file()` for reading small config files (e.g., `/etc/mxfs/node.uuid`). Kernel: `filp_open` + `kernel_read`. Userspace: `fopen` + `fread`. Returns bytes read or negative errno.
- 2026-02-18: Added `mxfs_pal_bdev_write_gather()` for writing multiple contiguous blocks in a single bio. Takes an array of buffer pointers (one per block), builds a multi-page bio, and submits with `submit_bio_wait()`. Splits into BIO_MAX_VECS (256) batches for large runs. Falls back to single `bdev_write` for nbufs==1. Used by block cache coalesced flush to reduce I/O syscall overhead.
- 2026-02-19: **Zero-copy bdev I/O optimization.** Replaced alloc_page()/memcpy/__free_page in `bdev_sync_io()` with `virt_to_page()`/`vmalloc_to_page()` to reference caller's buffer pages directly in the bio. Added `kaddr_to_page()` helper that routes vmalloc addresses through `vmalloc_to_page()` and all others through `virt_to_page()`. Handles non-page-aligned buffers via `offset_in_page()`. Applied the same zero-copy approach to `bdev_write_gather()`. Eliminates per-I/O page allocation, memcpy, and page deallocation overhead. Benchmark result: cold read from 1.39x to 1.00x parity with raw XFS.
- 2026-02-19: **Fix listener socket leak on unmount.** `mxfs_pal_tcp_shutdown()` called `kernel_sock_shutdown(SHUT_RDWR)` which on LISTEN-state sockets only sets shutdown flags but does NOT wake threads blocked in `kernel_accept()` (`inet_csk_accept` waits on the accept queue, not the error path). Fix: after `kernel_sock_shutdown`, set `sk_err = EINTR` and call `sk_error_report()` to force-wake all waiters including the accept queue. Without this, the accept thread hangs forever, `thread_join` blocks, and `tcp_close` on the listen socket is never reached — leaving port 7600 in LISTEN state and blocking rmmod.
- 2026-02-19: **Pipelined bio reads.** Replaced sequential submit_bio_wait() read path with concurrent multi-bio submission. New `bdev_pipelined_read()` builds up to 16 bios (16 MB), submits them all non-blocking via `submit_bio()`, then collects completions via `bi_end_io` callbacks. Factored bio construction into `build_bio()` shared by sync and pipeline paths. Added `struct mxfs_bio_ctx` (completion + status) and `struct mxfs_inflight` (heap-allocated to stay within stack frame limits). Write path remains synchronous for ordering guarantees. Benchmark: cold reads improved 6-14% (86.3 MB/s = 102% of raw XFS cold), warm reads improved ~12% at scale (108 MB/s for 500MB).
- 2026-02-19: **Added `mxfs_pal_udp_shutdown()`.** Mirrors `mxfs_pal_tcp_shutdown()` for UDP sockets: calls `kernel_sock_shutdown(SHUT_RDWR)` then sets `sk_err = EINTR` and `sk_error_report()` to force-wake threads blocked in `kernel_recvmsg()` or `kernel_sendmsg()`. Used by discovery stop path to unblock the recv thread immediately instead of waiting for the 500ms timeout to expire.
- 2026-02-19: **Added `mxfs_pal_thread_create_rt()`.** Creates a kthread with real-time (low) priority. Kernel: calls `sched_set_fifo_low()` (5.9+) or `sched_set_fifo()` (pre-5.9) after thread creation to set SCHED_FIFO at the lowest RT priority. Userspace: best-effort `pthread_setschedparam(SCHED_FIFO, min_priority)`, falls back silently if unprivileged. Used by lease renew and monitor threads to prevent starvation by CFS tasks under heavy iSCSI I/O.
- 2026-02-19: **Aggressive TCP keepalive in `mxfs_pal_tcp_set_opts()`.** Added keepalive timing parameters: idle=10s, interval=5s, count=3 (total ~25s to detect dead peer). Previously only `SO_KEEPALIVE` was enabled with Linux defaults (idle=7200s, interval=75s, count=9), taking ~2+ hours to detect a crashed node. Kernel PAL uses `tcp_sock_set_keepidle()`, `tcp_sock_set_keepintvl()`, `tcp_sock_set_keepcnt()` (available since 5.7, covers all target kernels 5.10+). Pre-5.7 fallback uses `kernel_setsockopt()` with `TCP_KEEPIDLE`/`TCP_KEEPINTVL`/`TCP_KEEPCNT`. Userspace PAL uses standard `setsockopt()`. Applied to both inbound (accept) and outbound (connect) sockets.
- 2026-02-19: **Added SO_RCVBUF/SO_SNDBUF (4MB) to `mxfs_pal_tcp_set_opts()`.** Sets both receive and send socket buffer sizes to 4MB (4194304 bytes) for DLM traffic headroom. Kernel PAL: sets `sk->sk_rcvbuf` and `sk->sk_sndbuf` directly under `lock_sock/release_sock`. Userspace PAL: `setsockopt(SOL_SOCKET, SO_RCVBUF/SO_SNDBUF)`. Applied before keepalive and TCP_NODELAY settings. Larger buffers reduce the chance of TCP backpressure during DLM message bursts at 4+ nodes.
- 2026-02-27: Added `mxfs_pal_bdev_write_fua()` for Force Unit Access writes. Uses `REQ_OP_WRITE | REQ_FUA` to bypass the disk write cache, ensuring data reaches stable storage before the call returns. Used by dir_cache flush paths for multi-node I/O coherency on VMware multi-writer VMDKs. Kernel PAL: passes the FUA flag to `bdev_sync_io()`. Userspace PAL: falls back to `bdev_write()` + `bdev_flush()`.
- 2026-03-02: **Bug 81: TCP receive-side transport improvements.** Two changes in `mxfs_pal_tcp_set_opts()`: (1) Added `sk->sk_rcvtimeo = msecs_to_jiffies(30000)` (30s receive timeout) right after the existing `sk_sndtimeo`. This makes `kernel_recvmsg()` return `-EAGAIN` after 30s instead of blocking indefinitely, allowing recv threads to periodically re-check shutdown flags and peer state. (2) Reduced `TCP_USER_TIMEOUT` from 600000ms (10 minutes) to 60000ms (60 seconds). The 10-minute value was excessively long — 60s is sufficient to ride out transient TCP congestion while still detecting dead connections in a reasonable time.
- 2026-03-03: **Bug 83: Reduced PAL-level TCP send timeout and retries.** Changed `sk_sndtimeo` from 5000ms to 2000ms and EAGAIN retry limit from 6 to 3 in `mxfs_pal_tcp_send()` and `mxfs_pal_tcp_set_opts()`. This reduces worst-case PAL send time from 30s (6 x 5s) to 6s (3 x 2s). The old 30s window held `peer->send_lock` long enough to cascade across 8+ node clusters, causing DLM traffic stalls and mass disconnects. The reduced window, combined with the removal of peer-level send retries (Bug 83 in peer.c), ensures that a failed send disconnects within 6s and lets discovery-driven reconnection (~2s) handle recovery. Changes: pal_linux_kern.c (`mxfs_pal_tcp_send` EAGAIN limit, `mxfs_pal_tcp_set_opts` sk_sndtimeo).
- 2026-03-03: **Increased socket buffers from 2MB to 4MB.** Changed `sk->sk_rcvbuf` and `sk->sk_sndbuf` from 2MB to 4MB in `mxfs_pal_tcp_set_opts()`. 4MB balances DLM burst absorption with tcp_mem scaling. At 8 nodes: 7 x 8MB = 56MB (under 115MB pressure threshold). At 32 nodes: 31 x 8MB = 248MB (may need tcp_mem tuning). Changes: pal_linux_kern.c.
- 2026-03-08: **Added SO_REUSEPORT to TCP listen socket.** `mxfs_pal_tcp_listen()` now sets `sk_reuseport = 1` (kernel) or `setsockopt(SO_REUSEPORT)` (userspace) on TCP STREAM sockets, matching the existing UDP multicast socket behavior. This allows multiple MXFS mounts on the same node to bind the same TCP DLM port (7600). Combined with volume_id validation in the peer handshake (peer.c), connections are routed to the correct mount context. Changes: pal_linux_kern.c, pal_linux_user.c.
- 2026-03-06: **Added bdev clone with offset.** New `mxfs_pal_bdev_clone_with_offset()` creates a lightweight clone of a block device handle with a `base_offset` that is transparently added to all I/O offsets. The clone shares the underlying block_device (kernel) or fd (userspace) -- the original owns the reference. `mxfs_pal_bdev_close_clone()` frees the clone without closing the device. Added `base_offset` and `is_clone` fields to `struct mxfs_bdev` in both kernel and userspace PAL. All I/O paths (build_bio sector calc, pread/pwrite offsets, SCSI CAW LBA, write_gather) apply `dev->base_offset`. Used by mount.c to create `xfs_dev` for the new front-of-device MXFS metadata layout. Changes: pal.h, pal_linux_kern.c, pal_linux_user.c.
- 2026-03-04: **Added `mxfs_pal_bdev_compare_and_write()` — SCSI COMPARE AND WRITE (CAW) primitive.** Atomic compare-and-swap at sector granularity. Reads sector at `offset`, compares against `compare_buf` (512 bytes); if match, atomically writes `write_buf` (512 bytes). Returns 0 on success, `-EAGAIN` on MISCOMPARE (caller retries), `-EIO` on I/O error, `-EOPNOTSUPP` if device doesn't support CAW. CDB: 16 bytes, opcode 0x89, FUA bit set, 1 logical block. Data-out: 1024 bytes (compare + write). Kernel PAL: navigates device model (`disk_to_dev()->parent` → `scsi_device`) and uses `scsi_execute_cmd()` (6.3+) or `scsi_execute()` (pre-6.3). Parses `scsi_sense_hdr` for MISCOMPARE (sense key 0x0E). Userspace PAL: uses SG_IO ioctl following the same pattern as `scsi_pr_out()`, parses both fixed (0x70/0x71) and descriptor (0x72/0x73) sense format for MISCOMPARE. Used for lock-free coordination on shared block devices.
- 2026-03-08: **Added `mxfs_pal_thread_join_timeout()`.** Timed thread join with millisecond timeout. Kernel PAL: `wait_for_completion_timeout()` on the `exited` completion, then `kthread_stop()` if the thread exited within the timeout. Returns 0 on success (thread exited), -ETIMEDOUT if the thread did not exit within the specified timeout. The thread handle is consumed on success but left valid on timeout (caller can retry or abandon). Userspace PAL: `pthread_timedjoin_np()` with computed `struct timespec` absolute deadline. Used by `mxfs_disklock_stop_heartbeat()` (Bug 99) to avoid hanging forever when the heartbeat thread is stuck in blocking disk I/O. Changes: pal.h, pal_linux_kern.c, pal_linux_user.c.
- 2026-03-08: **Added SO_REUSEPORT to UDP multicast sockets.** `mxfs_pal_udp_open()` now sets `sk_reuseport = 1` (kernel) or `setsockopt(SO_REUSEPORT)` (userspace) on UDP DGRAM sockets. Allows multiple MXFS mounts on the same node to bind the same discovery (7601) and lease (7602) multicast ports. Part of Bug 98 multi-LUN support. Changes: pal_linux_kern.c, pal_linux_user.c.
- 2026-03-09: **Added `mxfs_pal_bdev_read_prio()` — Priority block device read.** Uses `REQ_OP_READ | REQ_PRIO | REQ_SYNC` in the kernel to give DLM lock slot reads elevated priority in the block I/O scheduler. `REQ_PRIO` tells blk-mq schedulers (mq-deadline, bfq, kyber) to service the request ahead of regular data I/O. `REQ_SYNC` bypasses write-back coalescing to reduce latency. Uses `bdev_sync_io()` (not pipelined) since DLM reads are always 512 bytes. Provides effective queue separation between lock I/O and data I/O — critical at 32+ nodes where heavy data writes from multiple nodes can starve lock acquisition. Userspace PAL: delegates to `mxfs_pal_bdev_read()` (no priority concept in POSIX). Changes: pal.h, pal_linux_kern.c, pal_linux_user.c.
- 2026-03-11: **Added `mxfs_pal_get_random_bytes()`.** Fills a buffer with cryptographic-quality random data. Kernel: wraps `get_random_bytes()`. Userspace: reads from `/dev/urandom` with retry on EINTR. Used by mount.c to generate random node UUIDs when `/etc/mxfs/node.uuid` doesn't exist (replacing hostname-based UUID derivation). Changes: pal.h, pal_linux_kern.c, pal_linux_user.c.
- 2026-02-19: **Fix TCP keepalive not detecting hard-powered-off peers.** Added `TCP_USER_TIMEOUT` (25000ms) to `mxfs_pal_tcp_set_opts()`. TCP keepalive alone was insufficient for detecting nodes that are hard-powered-off (no RST, no FIN). The kernel's `tcp_keepalive_timer` checks `icsk_user_timeout` and aborts the connection once elapsed time since last ACK exceeds this value. Without it, the retransmit timer could keep the connection alive indefinitely even after all keepalive probes failed. Kernel PAL (5.7+): sets `inet_csk(sk)->icsk_user_timeout = 25000` directly via `lock_sock/release_sock`. Pre-5.7: uses `kernel_setsockopt(TCP_USER_TIMEOUT)`. Userspace PAL: `setsockopt(TCP_USER_TIMEOUT)`. Field available since Linux 2.6.37, covers all target kernels.
- 2026-03-19: **Added `mxfs_pal_bdev_write_async()` and `mxfs_pal_bdev_read_async()` — Pipelined bio write/read for O_DIRECT.** New `bdev_pipelined_write()` mirrors the existing `bdev_pipelined_read()` pattern: builds up to `MXFS_MAX_INFLIGHT_BIOS` (16) bios, submits them all non-blocking via `submit_bio()`, then waits for all completions via `bi_end_io` callbacks. Reuses the existing `build_bio()`, `mxfs_bio_end_io()`, and `struct mxfs_inflight` infrastructure. This replaces serial `submit_bio_wait()` in the O_DIRECT data write path, achieving real I/O parallelism (16 MB concurrently). The sync write paths (`mxfs_pal_bdev_write`, `bdev_write_gather`) remain unchanged for metadata, journal, and block cache operations where ordering matters. `mxfs_pal_bdev_read_async()` wraps the existing `bdev_pipelined_read()` for API symmetry. Userspace PAL: both async functions delegate to their sync counterparts (no bio concept in userspace). Changes: pal.h, pal_linux_kern.c, pal_linux_user.c. Updated PAL table: `bdev_write_async` = pipelined bio write (up to 16 concurrent), `bdev_read_async` = pipelined bio read (up to 16 concurrent).

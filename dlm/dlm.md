# MXFS Portable DLM Engine (libmxfs/dlm)

## Overview

The DLM (Distributed Lock Manager) engine manages the distributed lock table for multi-node coordination. It processes lock requests from the local inode/dir caches and from remote peers, enforces the standard 6-mode compatibility matrix (NL/CR/CW/PR/PW/EX), and handles lock queuing, granting, conversion, and BAST (Blocking Asynchronous Trap) notification.

Ported from `kernel/mxfs_dlm.c` with kernel APIs replaced by PAL abstractions.

## Architecture

### Files

- **dlm.h**: Data structures and API. Defines `mxfs_lock`, `mxfs_dlm_pending`, `mxfs_dlm_ctx`, callback types.
- **dlm.c**: Implementation of the lock table, compatibility checks, request processing, BAST, and mastering.

### Data Structures

- **mxfs_lock**: One entry per (resource, owner) pair. Hash-chained in the lock table.
- **mxfs_dlm_pending**: Tracks outstanding lock requests waiting for remote grant/deny. Uses mutex+cond for sleeping.
- **mxfs_dlm_ctx**: Per-mount DLM context. Contains the hash table, active node list, pending request table, and callback pointers.

### Lock Table

- 4096-bucket hash table, FNV-1a hash over `mxfs_resource_id` bytes
- Each bucket is a singly-linked list of `mxfs_lock` entries
- Protected by `table_rwlock` (PAL rwlock)

**Shared code note (§11 step 3, 2026-07-17):** the compatibility matrix
(`lock_compat`), `resource_hash_raw()`, and `resource_equal()` no longer
live in dlm.c — they were lifted verbatim into `dlm_shared.c`/`dlm_shared.h`
so dlm.c, dlm_caw.c, and the NET2 lock plane (`dlm/net2_shard.c`) share one
copy instead of three near-identical ones. dlm.c behavior is unchanged
(verified by `tests/net2/gate3_cawsanity.sh` forcing a CAW re-form and
re-running posix_multi + dlm_fairness). dlm.c now includes `dlm_shared.h`.

### Distributed Per-Resource Mastering

Each resource is mastered by exactly one node, determined by:
```
master = active_nodes[FNV1a_hash(resource_id) % active_node_count]
```

The active node list is maintained by `mxfs_dlm_update_active_nodes()` which sorts nodes by ID. When membership changes, the entire lock table is purged to prevent stale entries from bypassing the new master.

### Lock Request Flow

**Local master path** (`mxfs_dlm_lock()` when local node is master):
1. Check for existing lock (same resource, same owner) for conversion
2. Check compatibility with all GRANTED holders
3. Compatible: allocate lock entry as GRANTED, return immediately
4. Incompatible + NOQUEUE/TRYLOCK: return -EAGAIN/-EWOULDBLOCK
5. Incompatible: allocate as WAITING, collect BAST records for conflicting holders, release table_rwlock, set up pending entry, fire BASTs, sleep on pending entry until promoted

**Remote master path** (`mxfs_dlm_lock()` when remote node is master):
1. Build MXFS_MSG_LOCK_REQ message
2. Insert pending entry in hash table
3. Send to remote master via `send_cb`
4. Sleep on pending entry until grant/deny response arrives
5. On LOCK_GRANT: insert local lock entry

**Remote request processing** (`mxfs_dlm_process_remote_request()`):
1. Check for existing lock from same sender (conversion)
2. Check compatibility with all GRANTED holders
3. Compatible: allocate as GRANTED, send LOCK_GRANT
4. Incompatible: allocate as WAITING, collect BAST records, release lock, fire BASTs, return -EINPROGRESS

### BAST (Blocking AST) Mechanism

When a new lock request conflicts with an existing grant, the DLM fires a BAST to each conflicting holder. The BAST tells the holder to flush dirty data and release its lock.

**Deferred BAST pattern**: BASTs are collected into a `bast_record` array while `table_rwlock` is held, then fired via `fire_bast_callbacks()` after releasing the lock. This prevents deadlock: the BAST handler may call `mxfs_dlm_unlock()` which needs to acquire `table_rwlock`.

**BAST callback dispatch** (in mount.c `dlm_bast_cb()`):
- Local holder (`owner == local_node`): calls `mxfs_inode_cache_bast_cb()` and `mxfs_dir_cache_bast_cb()` to flush dirty data, release DLM lock, and drop from cache
- Remote holder (`owner != local_node`): sends `MXFS_MSG_LOCK_BAST` message over TCP to the holding node

### Waiter Promotion

After a lock release, `promote_waiters()` scans the chain for WAITING/BLOCKED entries that can now be granted (compatible with all remaining GRANTED entries). Promoted entries are:
- Local: signaled via pending entry completion
- Remote: sent LOCK_GRANT via TCP

### Callbacks

| Callback | Purpose |
|---|---|
| `grant_cb` | Notified when a queued lock is promoted to GRANTED |
| `bast_cb` | Notified when a conflicting request requires holder to release |
| `send_cb` | Sends DLM wire messages to remote nodes via peer TCP |
| `membership_cb` | Notified when membership changes and lock table is purged — caches must be invalidated |

### Key Functions

| Function | Purpose |
|---|---|
| `mxfs_dlm_create()` | Create per-mount DLM context |
| `mxfs_dlm_destroy()` | Destroy DLM, free all locks |
| `mxfs_dlm_lock()` | Acquire a lock (local or remote master) |
| `mxfs_dlm_unlock()` | Release a lock |
| `mxfs_dlm_lock_convert()` | Upgrade/downgrade a held lock |
| `mxfs_dlm_release_all()` | Release all local locks (unmount) |
| `mxfs_dlm_withdraw_release_all()` | Wire-release every lock the local node holds/queued on a force-shutdown withdraw (see History, sess10 fix) |
| `mxfs_dlm_purge_node()` | Remove all locks for a dead/departing node |
| `mxfs_dlm_purge_stale_for_resource()` | Remove stale remote holders for a specific resource |
| `mxfs_dlm_process_remote_request()` | Handle incoming LOCK_REQ from peer |
| `mxfs_dlm_process_remote_grant()` | Handle incoming LOCK_GRANT from master |
| `mxfs_dlm_process_remote_release()` | Handle incoming LOCK_RELEASE from peer |
| `mxfs_dlm_resource_master()` | Determine which node masters a resource |
| `mxfs_dlm_update_active_nodes()` | Update membership, purge stale locks |
| `mxfs_dlm_is_single_node()` | Returns true if active_nodes.count <= 1 |
| `mxfs_dlm_modes_compatible()` | Check 6-mode compatibility matrix |

## Dependencies

- PAL: rwlock, mutex, cond, alloc, time, sort, log
- mxfs_common.h: resource_id, node_id, volume_id types
- mxfs_dlm.h: wire protocol message types and structures
- dlm_shared.h: compatibility matrix, `resource_hash_raw()`, `resource_equal()`
  (shared with dlm_caw.c and the NET2 lock plane, since 2026-07-17)

## History

- 2026-02-15: Initial port from kernel/mxfs_dlm.c. Replaced kernel APIs (rw_semaphore, kmem_cache, completion, spinlock, ktime) with PAL equivalents.
- 2026-02-16: Fixed BAST deadlock. BAST callbacks were being invoked while holding `table_rwlock`, causing deadlock when the callback tried to call `mxfs_dlm_unlock()` which re-acquires the same lock. Fix: added `bast_record` struct and `fire_bast_callbacks()` to defer BAST firing until after `table_rwlock` is released. Applied to both `mxfs_dlm_lock()` and `mxfs_dlm_process_remote_request()`.
- 2026-02-16: Fixed cross-node BAST delivery failure. Root cause: `mxfs_dlm_update_active_nodes()` purges the entire lock table on membership change, but the inode/dir caches still have entries with stale `lock_mode` values, so BAST never fires (DLM finds no conflicts). Fix: added `membership_cb` callback that fires after lock table purge, wired to `dlm_membership_cb` in mount.c which calls `dir_cache_drop_all` and `inode_cache_drop_all` to flush dirty data and discard all cached lock state, forcing next access to re-acquire DLM locks from the correct master.
- 2026-02-16: Added `shutting_down` flag. When set, remote lock requests fail immediately with -ESHUTDOWN instead of sending TCP messages to potentially disconnected peers. Set during `mxfs_unmount()` before sending NODE_LEAVE.
- 2026-02-16: Fixed DLM lock timeout on unmount. Root cause: unmount sent NODE_LEAVE before flushing dirty caches; dir_cache_flush_all requires DLM locks via inode_cache_get_exclusive, but peers had already disconnected causing 30-second timeout. Fix: restructured unmount to flush all dirty data (dir/inode/block caches) while DLM and peers are still active, then set shutting_down, send NODE_LEAVE, release all DLM locks, and destroy caches.
- 2026-02-19: Fixed BAST not reaching all nodes at 3+ nodes (epoch-based stale lock detection). Root cause: during membership transitions, nodes update their active_nodes lists at different times via UDP discovery. A node that processes the membership change later than its peers could hold a cached DLM lock registered at a stale master. The new master doesn't know about this lock and won't send BASTs to the holding node, causing it to serve stale directory data indefinitely. Fix: (1) `mxfs_dlm_update_active_nodes()` now advances the DLM epoch on every membership change; (2) `struct mxfs_cached_inode` records `lock_epoch` when a DLM lock is acquired; (3) `cache_get_locked()` compares the cached epoch against the current DLM epoch on every cache hit -- if they differ, the cached entry is evicted and the lock is re-acquired from the correct master. This also protects against inodes that survive `drop_all` due to non-zero refcount during membership change processing. Changes: dlm.c, inode_cache.h, inode_cache.c.
- 2026-02-19: Added `mxfs_dlm_purge_stale_for_resource()` to break file lock starvation at 3+ nodes. Root cause: epoch-based eviction in inode_cache.c handles the inode cache side, but the DLM lock table on the new master can still hold stale remote lock entries from nodes that were the previous master. These stale entries represent locks that the remote node already dropped during its own epoch eviction, but the current master never received a LOCK_RELEASE for them. New lock requests queue behind these ghost holders and time out because no BAST will ever succeed. The new function purges all remote lock entries for a specific resource and promotes any unblocked waiters. Called from inode_cache.c when mxfs_dlm_lock() times out. Changes: dlm.h, dlm.c, inode_cache.c.
- 2026-02-19: Fixed BAST not reaching all PR holders at 4+ nodes. Three issues: (1) `dlm_bast_cb()` in mount.c silently discarded `mxfs_peer_send()` return value for remote BASTs — transient TCP failures caused holders to never receive BASTs and serve stale data. Fix: 3-retry loop with 50ms delay and ERR logging on exhaustion. (2) `mxfs_dlm_lock()` local master path set up the pending entry AFTER firing BASTs — fast holders could release and signal the pending before it existed, losing the grant signal. Fix: moved `pending_alloc/insert` before `fire_bast_records`. (3) `mxfs_inode_cache_bast_cb()` returned without releasing the DLM lock when the inode was not in cache — stale holder entry at master blocked conflicting requests. Fix: attempt `mxfs_dlm_unlock()` even when inode not cached. Changes: mount.c, dlm.c, inode_cache.c.
- 2026-02-19: Fixed simultaneous unmount cross-node deadlock. When 2+ nodes unmount at the same time, `mxfs_unmount()` calls `dir_cache_flush_all()` which calls `mxfs_inode_cache_get()` which calls `mxfs_dlm_lock()`. Each node needs a lock mastered by the other (also shutting down) causing both to enter D-state. Root cause: `shutting_down` was set AFTER cache flushes and only covered the remote-master lock path. Fix: (1) moved `shutting_down` check to the top of `mxfs_dlm_lock()`, before the remote/local branch, so both paths return `-ESHUTDOWN` immediately during shutdown; (2) removed the now-redundant remote-only check. Changes: dlm.c.
- 2026-02-19: Fixed DLM lock hang after dead-node recovery. Root cause: when a node crashes and `mxfs_dlm_update_active_nodes()` purges the lock table, threads sleeping in `pending_wait()` were not woken. Two scenarios: (1) Remote-master path: thread sent LOCK_REQ to the now-dead node and was waiting for a LOCK_GRANT that would never arrive. The thread would block for `MXFS_LOCK_WAIT_TIMEOUT_MS` (120s) in D-state, blocking all filesystem operations behind it via VFS-level dentry locks (`d_alloc_parallel`, `do_unlinkat`). (2) Local-master path (incompatible queue): thread's WAITING lock entry was freed by the table purge, but the thread was still sleeping on its pending entry. Subsequent cleanup would access freed memory (use-after-free on `newlk`). Fix: (1) added `fail_all_pending()` which iterates all pending entries and completes them with `MXFS_DLM_RETRY`, called from `update_active_nodes` after purging the lock table. (2) Refactored `mxfs_dlm_lock()` into `dlm_lock_impl()` (core logic) + `mxfs_dlm_lock()` (retry wrapper). On `MXFS_DLM_RETRY`, the wrapper retries up to 3 times with the updated master assignment. The retry typically succeeds immediately because the surviving node is now master for all resources with an empty lock table. (3) In the local-master incompatible path, `MXFS_DLM_RETRY` from `pend->status` skips the `newlk` cleanup (the entry was already freed by the table purge), preventing use-after-free. Changes: dlm.c.
- 2026-02-27: **Added error checking to send_grant().** The `ctx->send_cb()` return value in `send_grant()` was previously ignored. Now checks the return value and retries once after a 10ms delay on failure. If the retry also fails, logs a warning with the target node, error code, and resource details. The requesting node's `pending_wait` timeout handles ultimate recovery. Also added null-check and warning to `fire_bast_records()` when `bast_cb` is NULL. Changes: dlm.c.
- 2026-02-25: Added DLM_TRACE debug logging for inode 128 (root dir) to diagnose dual-EX grant issue where both nodes hold EX simultaneously after BASTs stop firing. Conditional on `resource->ino == 128 && resource->type == MXFS_LTYPE_INODE` (dlm.c) and `ino == 128` (inode_cache.c) to avoid noise. Traces: dlm_lock entry, local master grant/already-granted/add-to-waiters paths, process_remote_request entry with all existing holders dumped, conflict check result, BAST fire decisions and targets, fire_bast_records per-BAST fire, dlm_unlock entry removal and promote_waiters result, promote_waiters per-promotion grants, process_remote_release entry/found/ENOENT, inode_cache cache_get_locked EX-skip hit, inode_cache_put bast_pending vs EX-left-cached, bast_cb entry/deferred/inline. All prefixed "DLM_TRACE:" for grep. Added local `mode_name()` helper to inode_cache.c. No logic changes. Changes: dlm.c, inode_cache.c.
- 2026-02-28: **Bug 67** — Fixed DLM lock deadlock after membership epoch change. Root cause: when a membership change occurs, `fail_all_pending()` wakes all pending lock requests with `MXFS_DLM_RETRY`. The retry loop in `mxfs_dlm_lock()` calls `dlm_lock_impl()` again, which recalculates the master (may be different). But if the old master's grant arrives AFTER the retry sends a new request to the new master, the old grant completes the new pending entry (stale grant from wrong epoch). The new request to the new master then never gets a matching pending entry, causing a hang. Additionally, the retry loop only did 3 retries, which exhausted under repeated rapid membership changes, returning -EAGAIN and causing permanent lock starvation. Fix: (1) Added `request_epoch` field to `struct mxfs_dlm_pending` to record the DLM epoch when a remote lock request is sent. (2) In `dlm_lock_impl()` remote-master path, `pend->request_epoch` is set to `ctx->current_epoch` after `pending_alloc()`. (3) `pending_signal_resource()` now accepts an `epoch` parameter. When non-zero, it only matches pending entries whose `request_epoch` matches the grant epoch; stale grants from a previous epoch are logged at DEBUG level and silently discarded. Internal callers (promote_waiters, purge_node, etc.) pass 0 to match any pending entry. (4) `mxfs_dlm_process_remote_grant()` now accepts and passes `grant_epoch` from the wire message header to `pending_signal_resource()`. (5) `peer_msg_cb()` in mount.c extracts `resp->hdr.epoch` and passes it to the updated grant handler. (6) `fail_all_pending()` is unchanged -- it still wakes ALL pending entries regardless of epoch. (7) Increased retry count from 3 to 10 to handle multiple rapid membership changes. Changes: dlm.h, dlm.c, mount.c.
- 2026-02-23: **Bug 51** — Fixed dual-EX grant race causing data corruption on 2-node concurrent writes. Root cause: `mxfs_dlm_process_remote_request()` had an "already granted" shortcut that returned LOCK_GRANT immediately when the sender already had a GRANTED entry at sufficient mode, without checking for conflicts with other holders or pending waiters. This was exploitable via a send-ordering race: when a node's BAST handler (recv thread) and its next lock request (main thread) race for `peer->send_lock`, the LOCK_REQ can arrive at the master before the preceding LOCK_RELEASE. The master finds the sender's OLD GRANTED(EX) entry and takes the shortcut, sending LOCK_GRANT without BAST. The subsequent LOCK_RELEASE removes the old entry, leaving the master with no record of the sender's grant while the sender believes it holds EX. Both nodes now hold EX simultaneously, each allocating data blocks from different AGs; the last to flush the inode wins, orphaning the other node's data. BASTs stop firing entirely because the master has no conflicting entries. Fix: three changes: (1) In `mxfs_dlm_process_remote_request()`, the "already granted" shortcut now verifies that no other node has a conflicting GRANTED lock AND no other node has a WAITING/BLOCKED request before re-affirming the grant. If conflicts or waiters exist, the old entry is removed, any unblocked waiters are promoted via `promote_waiters()`, and the new request falls through to the normal queue-and-BAST path. (2) In `mxfs_dlm_process_remote_release()`, the fallback that removed WAITING/BLOCKED entries when no GRANTED entry was found has been removed. This prevents the stale LOCK_RELEASE (arriving after the re-request handling already removed the old GRANTED entry) from destroying the sender's new WAITING entry. (3) Defense-in-depth: the local-master "already granted" shortcut in `dlm_lock_impl()` now performs the same safety check. Changes: dlm.c.
- 2026-03-10: **Bug 106** — Fixed DLM grant epoch mismatch causing lock timeouts at 3+ nodes with incremental joins. Root cause: `send_grant()` stamped the grant message with `ctx->current_epoch` (the master's local epoch). But the stale-grant filter in `pending_signal_resource()` (Bug 67) discards grants where `grant_epoch > request_epoch`. Since each node counts membership changes independently, the master's epoch can be higher than the requester's epoch (e.g., master saw 3 transitions while requester saw 2). Valid grants are silently discarded, causing 30-second DLM lock timeouts for the affected nodes. Any operation on the filesystem hangs. Fix: (1) Added `mxfs_epoch_t request_epoch` field to `struct mxfs_lock` to store the requester's epoch when a WAITING entry is created. (2) Changed `send_grant()` to accept an explicit `epoch` parameter instead of always using `ctx->current_epoch`. (3) Direct grants in `process_remote_request()` pass the request's epoch. (4) Waiter promotions (from unlock, purge_stale, BAST response) pass `wk->request_epoch`. (5) Added `request_epoch` parameter to `mxfs_dlm_process_remote_request()` signature; mount.c passes `req->hdr.epoch`. The requester now always receives a grant stamped with its own epoch, so the Bug 67 filter never rejects valid grants. Changes: dlm.h, dlm.c, mount.c.
- 2026-03-11: Added `mxfs_dlm_is_single_node()` — queries `active_nodes.count` under mutex. Used by inode_cache.c and dir_cache.c to skip `invalidate_range` and `bdev_flush` on single-node mounts where the block cache is always authoritative. No other node can modify blocks, so cache invalidation is unnecessary. When a second node joins, count increments and invalidation resumes automatically.
- 2026-03-04: **Transport-agnostic dispatch typedefs.** Moved `mxfs_dlm_lock_fn`, `mxfs_dlm_unlock_fn`, and `mxfs_dlm_convert_fn` typedefs from mount.h to dlm.h so they are available to consumers (inode_cache.h, alloc.h) without circular include dependencies. These typedefs define the transport-agnostic function pointer signatures for DLM lock/unlock/convert operations. Changes: dlm.h (added typedefs), mount.h (removed duplicate typedefs).
- 2026-07-17 (NET2 §11 step 3, gate 3 GREEN): **CAW-neutral shared-code lift.** `resource_hash_raw()`, `resource_equal()`, and the 6-mode `lock_compat` matrix were moved verbatim out of dlm.c into the new `dlm_shared.c`/`dlm_shared.h` (also absorbs dlm_caw.c's byte-identical `fnv1a_hash` and its two `mxfs_pal_popcount64` variants, and the v0.3.83 EX/PW single-holder popcount validity check as `caw_slot_holders_popcount_ok()`). One copy now backs dlm.c, dlm_caw.c, and the NET2 lock plane (`dlm/net2_shard.c`). Behavior-neutral: verified via `tests/net2/gate3_cawsanity.sh` (forced CAW re-form + posix_multi + dlm_fairness on test1/test2, 211/211 + 5/5 PASS). dlm.c now `#include "dlm_shared.h"`. Changes: dlm.c, dlm_caw.c, dlm_shared.c/h (new).
- (uncommitted, ccloop 72513a13 sess10) **`mxfs_dlm_withdraw_release_all()` — wire-release on force-shutdown withdraw.** RULE-4 root cause for a 32-node fio cascade: when a node's filesystem force-shuts down, it can no longer service BASTs for the locks it still holds, but those GRANTED entries (and any queued WAITING entries) remained live in every master's lock table. A peer with a conflicting request against one of those entries then stalled to its terminal 120s lock-wait timeout and force-shut down itself — one root-cause node produced five cascading peer shutdowns in one fio@32 run (peers died with rc=-110 on ino=128 whose PR holder set included the dead node). Fix: `mxfs_dlm_withdraw_release_all(ctx)` snapshots every `mxfs_lock` entry owned by the local node across all buckets (two-pass count-then-fill under `table_rwlock`, released before unlocking) and runs the normal `mxfs_dlm_unlock()` path on each resource — locally-mastered entries get `promote_waiters()` + grant/BAST as usual; remotely-mastered entries send `LOCK_RELEASE`. A dead FS holds no valid cache, so releasing everything on withdrawal is always safe; peers then promote immediately instead of waiting out the full timeout against an unreachable holder. Wired from the withdraw path in `dlm/v5_mount.c` (TCP-DLM ctx only — CAW's disklock-heartbeat-driven purge already handles the equivalent case for the CAW transport). Changes: dlm.c (new function), dlm.h (declaration), v5_mount.c (call site).

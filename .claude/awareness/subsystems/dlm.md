# dlm (Distributed Lock Manager)

**Owner files**: `dlm/` (21 files, ~20K LOC), `include/` (4 headers), `compat/` (1 file)
**Last updated**: 2026-05-08

## Purpose

Cluster coordination layer. Provides per-resource (AG, inode) DLM locks across nodes via two transports: **CAW** (compare-and-write on the shared LUN's slot table — primary, default) and **TCP** (network-based — fallback for hardware where SCSI CAW is unreliable). Also hosts: SCSI PR fencing, disklock heartbeat + slot claiming, peer discovery (UDP multicast), lease management, dead-node journal recovery.

## Public API (top-level v5 surface)

```c
mxfs_v5_dlm_init(opts) -> *ctx                — Initialize cluster ctx (xfs_super.c calls)
mxfs_v5_dlm_shutdown(ctx)                     — Tear down at unmount
mxfs_v5_dlm_ag_lock(ctx, agno) -> int         — CAW grant for AG (slow path of ag_dlm_lock)
mxfs_v5_dlm_ag_unlock(ctx, agno)
mxfs_v5_dlm_inode_lock(ctx, ino, mode) -> int
mxfs_v5_dlm_inode_unlock(ctx, ino)
mxfs_v5_dlm_get_node_slot(ctx) -> uint32      — disklock-claimed slot 0..63
mxfs_v5_dlm_is_single_node(ctx) -> bool
mxfs_v5_dlm_purge_node(ctx, node_mask)        — drop dead node's grants
mxfs_v5_dlm_advance_epoch(ctx) / get_epoch    — DLM epoch (membership change)

mxfs_dlm_caw_create(dev, base, node, slot, uuid, max_held) -> *ctx   — CAW engine
mxfs_dlm_caw_destroy(ctx)
mxfs_dlm_caw_set_bast_cb(ctx, cb, data)
mxfs_dlm_caw_lock/unlock/convert
mxfs_dlm_caw_purge_dead_nodes(ctx, dead_mask) -> npurged

(legacy mxfs.1-style API in dlm/dlm.h still present for user-space tools)
```

## Key Data Structures

```c
struct mxfs_v5_dlm_opts {
    int      transport;         // CAW=0, TCP=1, AUTO=2
    uint64_t disklock_offset;
    uint64_t journal_offset;
    uint32_t max_nodes;
    void    *bdev;
    uint8_t  volume_uuid[16];
    int      max_dlm_lock_caw;  // v5 sess33: cap on held CAW locks (0=default)
};
struct mxfs_dlm_caw_ctx {
    mxfs_bdev_t      *dev;
    uint64_t          base_offset, lock_region_offset;
    mxfs_node_id_t    local_node;
    uint8_t           node_slot; uint64_t node_bit;
    struct { uint32_t *slots; int count; ... } held;  // dynamic, sized by max_held
    int               max_held;                       // v5 sess33: was static MXFS_CAW_MAX_HELD
    struct mxfs_caw_mem_lock *mem_locks;              // dynamic, single-node fast path
    int               mem_lock_count;
    bool              single_node;
    /* threads, sockets, callbacks, stats */
};
```

## Internal Architecture

**Slot table.** `MXFS_CAW_MAX_SLOTS=65536` slots on disk in the lock region (after disklock heartbeat area). Each slot is 64 bytes containing magic, generation, holders_ex/pr bitmasks, granted_mode, requested_mode, resource_id (32 bytes). Hash from `mxfs_resource_id` → starting slot index, linear probe.

**CAW lock acquire** (`mxfs_dlm_caw_lock`): `find_slot` (read+probe) → `caw_slot` CAS submitting our want → `caw_wait_for_grant` poll loop until granted or 120s timeout (`MXFS_CAW_WAIT_TIMEOUT_MS`). Poll with backoff 1ms→25ms.

**BAST poll thread** (`bast_poll_fn`): kthread reads our slot table entries every `MXFS_CAW_BAST_POLL_MS=200` (idle) or `MXFS_CAW_BAST_POLL_FAST_MS=100` (under contention; was 5ms — sess33 storm fix). When peer's request bit set on a slot we hold, fires `bast_cb` → upper layer (xfs) handles drain+release.

**TCP transport** (sess27, v5_mount.c): full TCP DLM via `mxfs_dlm_ctx`. Used when `mxfs.force_transport=1` or auto-detected from peers' transport. Coexists with CAW; v5 ctx picks one at init.

**Single-node bypass:** When `dlm_caw_ctx->single_node=true` (no peers seen), lock/unlock operate purely in `mem_locks[]` without disk I/O. On single→multi transition, `mxfs_dlm_caw_flush_held_to_disk` writes them all out.

**Disklock heartbeat:** 64 slots × 512 bytes at `disklock_offset`. Each node claims one slot and writes a heartbeat every few seconds; dead slots (heartbeat stale > timeout) are reclaimable. Slot index → node_bit (1<<slot) used everywhere as the cluster identity.

## Cross-Subsystem Dependencies

| Depends On | How | Notes |
|---|---|---|
| pal | `mxfs_pal_*` for I/O, threading, mutex, time, sockets | All platform calls go through PAL |
| include | Public headers: `mxfs_resource.h`, `mxfs_node.h`, etc. | Type definitions |

| Depended On By | How |
|---|---|
| xfs | `mp->m_mxfs_dlm` opaque; calls `mxfs_v5_dlm_*` and indirectly `mxfs_dlm_caw_*` | Primary consumer |
| pal/linux/xfs_super.c | Calls `mxfs_v5_dlm_init` from fill_super | Sets `m_mxfs_dlm` on mount |

## Invariants

1. **CAW slot table size is fixed at `MXFS_CAW_MAX_SLOTS=65536`** — on-disk layout. `max_held` (per-mount cap on locally-tracked held locks) MUST be ≤ this.
2. **Transport selection (CAW vs TCP) at mount time:**
   - **Joining existing cluster:** adopt whatever transport peers are using. No override.
   - **Forming new cluster (no peers):** probe CAW first; fall back to TCP if CAW probe fails.
   - **Command-line `mxfs.force_transport=1`** applies ONLY when forming a new cluster.
     Joining an existing cluster IGNORES the override (you must conform to peers).
   Once a cluster exists, transport is fixed; switching requires full unmount on every node.
3. **Disklock slot 0..63 is unique per live node.** Two nodes claiming the same slot = corruption. `mxfs_disklock_claim_slot` enforces via CAS on heartbeat.
4. **`mxfs_v5_dlm_ag_lock` may sleep up to 120s.** Callers MUST NOT hold short-term mutexes (xfs `pag_dlm_acquire_lock` excepted, since iodone path doesn't use it).
5. **Stale BAST messages must be tolerable.** UDP multicast can duplicate/lose; receiver must treat BAST as advisory + verify slot state on disk.
6. **`held.slots[]` and `mem_locks[]` are heap-allocated, sized by `max_held`** (v5 sess33). Pre-sess33 they were `[MXFS_CAW_MAX_HELD]` arrays — too small (4096) for real workloads.

## Known Pitfalls

- **`MXFS_CAW_MAX_HELD` capacity:** legacy default 4096 was below typical workload demand (element-web rsync alone uses ~5400 inodes per node). v5 sess33 default bumped to 32768 + dynamic alloc + per-mount override via `dlm_lock_max` module param + `mxfs_cache_caps.dlm_lock`. Hitting the cap → `disk lock table full` flood + perf collapse.
- **5ms BAST poll storm:** at 256 slots/cycle × 5ms = 51K reads/sec, saturates the LUN's SCSI queue at 16+ nodes. Bumped to 100ms in v5 sess33 (mxfs.1 sess74 finding). UDP multicast BAST is the primary fast path; disk poll is just a backup.
- **Single→multi transition flush:** `mxfs_dlm_caw_flush_held_to_disk` runs synchronously on transition. If lots held in memory, this is slow. Triggered when first peer joins the cluster.
- **CAW retry exhaustion:** `MXFS_CAW_MAX_RETRIES=100`. Beyond that returns -EAGAIN. Caller (xfs alloc paths) must handle, typically by trying a different AG. Don't increase blindly — sess29 v0.3.79 tried 500, made things WORSE (longer retry windows widened race exposure).

## TCP DLM grant-generation protocol (sess-tcp, build 404BC55C)

The 2-node `tcp_dlm_scaling` ~50% double-grant (two nodes both holding dir-EX →
durable lost-update) was fixed by a per-grant **generation token**. Wire:
`mxfs_dlm_lock_resp.grant_gen` + `mxfs_dlm_lock_release.grant_gen`
(include/mxfs/mxfs_dlm.h); `struct mxfs_lock.grant_gen` + `mxfs_dlm_ctx.grant_gen_next`
(dlm.h). `dlm_next_gen(ctx)` (monotonic, never 0, under table_rwlock) stamps every
GRANTED transition; `send_grant` carries it; the client mirror stores it and echoes
it in its RELEASE. Rules (dlm.c):
- `process_remote_request`, sender already GRANTED at mode>=req -> **always RE-AFFIRM**
  (keep entry, bump gen, re-send grant). NEVER remove+promote a waiter (that was the
  proven double-grant: the holder never released). Replaced the old Bug-51 still_safe
  block + stale-removal+promote branch.
- `process_remote_release` IGNORES a stale release (release.grant_gen != entry.grant_gen,
  both nonzero) -- the holder re-acquired since. gen==0 -> unconditional remove (liveness
  fallback for any pre-gen message).
- `process_remote_grant` (client): `pending_signal_resource` now returns matched; UPDATE
  an existing mirror in place (no dup); if !mirror && !matched -> UNSOLICITED grant (a
  re-affirm that arrived after we released) -> REJECT it (send gen-stamped RELEASE) to
  avoid a phantom-EX hang.
Both dispatchers (v5_mount.c, mount.c) extract grant_gen. CAW transport is NOT affected
(it never routes through process_remote_*).

## sess39 — membership split-brain fix (8/tcp dir_reuse catastrophic)

Two DLM coherency fixes (default-on; `tcp_death_grace_ms=15000`, `memb_settle_ms=6000`):
- **Deferred-TCP-death** (`v5_mount.c`): `v5_peer_disconnect_cb_tcp` marks a disconnected
  peer SUSPECT (`tcp_suspect_since[]`) instead of immediately purging+unregistering+
  refreshing. Grace-checker thread `v5_tcp_death_worker_fn` calls `v5_tcp_declare_dead`
  (the old purge/unregister/refresh) only if the peer fails to reconnect within the grace;
  `v5_peer_connect_cb_tcp` cancels on reconnect. Stops a ~7s transient TCP stall from
  flapping membership (8→7→8) → re-master → split-brain concurrent EX → dir corruption.
  Genuine death still caught by `v5_lease_expire_cb`.
- **EX-grant membership-settle gate** (`dlm.c`): `dlm_lock_impl` blocks an EX acquire
  (bounded 60s) while `dlm_membership_settling()` — the active set changed within
  `mxfs_memb_settle_ms` (new `ctx->last_memb_change_ms`, stamped in
  `mxfs_dlm_update_active_nodes`). Defers exclusive work until mastership converges
  (formation 1→N ramp + real death). Single-node + steady-state never gate.

RESIDUAL (unfixed): rare steady-state xfsaild zombie reflush (`readdir=799`) — see sess40.

## sess40 — `readdir=799` is a TCP DLM transport flap (not buffer-layer); flap-prevention fix

**REFRAME (PROVEN, RULE 4):** the dir_reuse single-dirent durable loss correlates 1:1 with a
transient ~500ms TCP flap (`TCP peer N disconnected — deferring death / reconnected — flap
absorbed`). The loss happens even at ROUND 1 on a fresh dir; all 8 nodes agree; `P-DATACLOBBER`,
`P25-RELVERIFY`, `P40-WRBARRIER` all SILENT (so not a stale dir-block write / release gap / late
bio — 39 prior sessions chased the wrong layer). sess39 deferred-death stops the flap churning
MEMBERSHIP, but the socket TEARDOWN still DROPS in-flight DLM grant/release/BAST messages
(fire-and-forget, never retransmitted) → lost-update → 1 dirent gone → cascades to
`DABUF_MAP_HOLE` shutdown. Both 8/tcp failure modes share this root (flap >15s → declared-dead →
split-brain mass-fail; flap <15s → 1-dirent loss).

**FIX (KEPT, `dlm/peer.c::mxfs_peer_send`):** a TRANSIENT send failure (`-ETIMEDOUT`/`-EAGAIN` =
peer's receiver slow / sndbuf full under the 8-node storm, NOT dead) no longer
`mxfs_pal_tcp_shutdown()`s the socket + fires `disconnect_cb` (which caused the flap). It returns
`-EAGAIN` keeping the connection up (caller retries on the same live socket; TCP still holds the
buffered bytes). Only a HARD error (ECONNRESET/EPIPE/ENOTCONN) tears down + reconnects. True
death still caught by TCP keepalive (~19s, `kern.c` set_opts keepidle=10/intvl=3/cnt=3) + UDP
lease (~75s). Result: 8/tcp dir_reuse 3/6 → **6/8**; 2/tcp 3/3 (no regression). Build `A985424B`.

**STILL NOT 100%** — residual = the deeper DLM message-reliability gap (hard-error flaps still
lose messages). **NEXT (GPT-5.5, 2 consults on file):** reliable midcomms (per-peer seq +
cumulative ack + resend-unacked-on-reconnect + receive-side dedup) + grant-generation cookies on
GRANT/RELEASE/BAST; audit "master never grants EX without a generation-matched RELEASE" and "every
release path drains like the BAST path" (under a correct DLM a lost msg should STALL, not corrupt
— there's a secondary corruption bug). ccmemory `sess40-REFRAME-799-is-tcp-flap-not-buffer-barrier-noop`,
`sess40-FIX-tcp-flap-prevention-send-no-teardown`.

## Historical Bugs

- **sess26 SCSI CAW non-persistence under stress:** kernel `scsi_execute_cmd` reported CAS-success without persisting writes when many CAS ops piled up. Sidestepped by sess27 TCP transport (still default-CAW, TCP via `force_transport=1`). v0.3.128 manual-bio path partially mitigates within CAW.
- **sess21 LIO FUA drop:** LIO target silently strips SCSI FUA bit (per `target_core_iblock.c:772`). Read-side coherency broken. Fix: `mxfs_pal_scsi_read_fua_bdev` issues SCSI READ(16) with FUA bit through PAL, plus `_XBF_FUA_FRESH` flag in xfs.

## Files

- `dlm_caw.{c,h}` — CAW engine, slot table, BAST poll thread (4500 LOC)
- `dlm.{c,h}` — TCP DLM (legacy + sess27 TCP transport hook)
- `peer.{c,h}` — TCP peer manager
- `discovery.{c,h}` — UDP multicast discovery
- `lease.{c,h}` — node lease + dead-node detection
- `disklock.{c,h}` — heartbeat + slot claiming
- `scsipr.{c,h}` — SCSI PR fencing
- `journal.{c,h}` — per-node journal slicing + dead-node replay
- `mount.{c,h}` — legacy mxfs.1-style `mxfs_mount` (user-space tools only)
- `v5_mount.{c,h}` — v5 kernel-side `mxfs_v5_dlm_init`

## sess4 (ccloop a16ec5f2) — unlock-fallback live-request protection (dlm.c/dlm.h)

- **ROOT FIX (proven runs 19/20 via P4L %px lifecycle trace):** `mxfs_dlm_unlock`'s
  WAITING/BLOCKED fallback used to reap ANY same-owner entry; bucket chains are
  LIFO so it ate a CONCURRENT local thread's live in-flight request → the
  requester's `newlk` dangled → kmalloc recycled the memory for a peer's entry →
  the requester's 1000ms timeout freed the recycled LIVE entry (run19: a peer's
  GRANTED EX gen 8210) → holder vanished from master table → immediate re-grant
  → CONCURRENT EX → stale-base dir RMW → durable dirent loss.
- `struct mxfs_lock.pend_waiter` (dlm.h): identity-only link to the local
  waiter's pending. Set when dlm_lock_impl queues WAITING (pending now allocated
  BEFORE the entry becomes table-visible), cleared at promote_waiters promotion
  and at the requester's own timeout-unlink. NEVER dereferenced.
- `mxfs_dlm_unlock` fallback skips entries with `pend_waiter != NULL`
  (P4U-SKIP-INFLIGHT — fires ~20-130×/run under dir_reuse churn, each one a
  prevented request-eat). Truly abandoned leftovers (NULL) still reaped.
- Timeout path frees newlk only if owner==local && WAITING/BLOCKED &&
  `pend_waiter == pend` (P4G-TIMEOUT-FREE-ALIAS otherwise; 0 post-fix).
- Probes: P4L-ALLOC/FREE/PROMOTE (%px, ino<=256, cap 400k) in
  lock_alloc/lock_free/promote_waiters.
- Verified: runs 21-26 = 0 P-DOUBLEGRANT / 0 MX-DOUBLEGRANT / 0 readdir dirent
  loss (previously every 8/tcp dir_reuse run lost dirents).

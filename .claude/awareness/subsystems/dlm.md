# dlm (Distributed Lock Manager)

**Owner files**: `dlm/` (21 files, ~20K LOC), `include/` (4 headers), `compat/` (1 file)
**Last updated**: 2026-07-25 (sess6: v0.11.92 orphan-grant NAK); 2026-08-02 (sess43: recovery GUARD slot flag + lease-timeout semantics — see final section)

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

## sess5 (ccloop-4dd7) — TCP join hardening (v0.11.72/73)
- `v5_peer_connect_cb_tcp` (v5_mount.c): an INBOUND/fallback TCP connect can be a node's
  first sight of any peer; it now fires `peer_joined_notify_fn` (XFS flush + DLM-cache
  invalidation) BEFORE lease-register/refresh when still single-node. Without it the later
  discovery announcement early-returns on `mxfs_lease_has_node` and the single→multi
  transition never runs on that node → phantom holds → split-brain (pve9 pair root #7).
- MEMBERSHIP-SETTLE GATE (both TCP and CAW mount branches, v5_mount.c): if the disklock
  slot table shows ACTIVE foreign slots at mount, the mount blocks (≤15s, 250ms poll)
  until the lease view covers them (`P-MEMB-SETTLE-TIMEOUT` on dead slots). Prevents the
  joiner's first write from self-granting on a stale base (root #8: durable dirent loss).
  The "DLM initialized" log line MUST print BEFORE this gate — run.sh's convergence awk
  resets its beacon window at that line.

## v0.11.74-76 — SCSI PR teardown ordering + slot release (physical QNAP campaign, 2026-07-24)

- **TEARDOWN-ORDER INVARIANT: PR unregister must FOLLOW the final XFS log write.**
  `xfs_fs_put_super` calls `mxfs_v5_dlm_detach_pr_key(v5dlm)` (v5_mount.h) BEFORE
  `mxfs_v5_dlm_shutdown`, then `mxfs_pal_scsi_pr_unregister_bdev(bt_bdev, key)`
  AFTER `xfs_unmountfs`. Unregistering inside v5 shutdown fenced the node's own
  unmount record on WE-RO-enforcing targets (EBADE log-error shutdown on every
  clean non-holder umount; unmount record lost → recovery next mount). Never
  reorder this back. New: `mxfs_scsipr_key/abandon` (scsipr.h).
- **`mxfs_disklock_release_slot(ctx)`** (disklock.h): clean teardown clears the
  heartbeat record's ACTIVE flag (FUA). Called from v5 shutdown when
  `!ctx->withdrawn` — withdraw/crash keeps the record ACTIVE so peers detect
  death + recover the slice. Without it every tenure ghost-taxes later mounts.
- **Settle gate ghost discrimination**: both gates (TCP+CAW) run a one-time
  liveness rescan (`get_stale_slot_mask` threshold=5000) if not settled after
  2s; frozen slots are discounted (`P-MEMB-GATE-GHOSTS`), worst case ~7s vs 15s.
  All-live joins settle <2s and never pay it.
- **TCP branch aborts mount on PR register failure** (parity with CAW): device
  with PR that refuses REGISTER = unfenced node under possible WE-RO → abort.
  One-shot injection `mxfs.dbg_pr_register_fail` (kern.c) verifies the path.
- **QNAP TS-453 Pro PR is NON-CONFORMANT**: purges ALL registrations on session
  logout/login without PRgen bump; UNREGISTER doesn't bump gen; enforcement of
  WE-RO vs unregistered writers is strict. PR on this target is advisory-only —
  D4 (preempt hygiene) + D8 (periodic PR self-check w/ self-fence) still open.
- **OPEN D7**: joiner root-ino EX acquire stalls 4.7-20s (variable) when holder
  has unflushed root-EX at join; joiner-side, self-mastered, pre-grant wait,
  attempts=1. Needs request-ID timestamps (see memory physrig-fixes-v74-76).
- **OPEN D6**: clean umount sends no goodbye → surviving peer's umount grinds
  the full 40s tcp_death_grace with "lock request retrying" spam.

## v0.11.77-80 — fail-closed mount, view-proof settle, goodbye, PR fence program (ccloop c7ee71c6 sess1, 2026-07-25)

- **v0.11.77 (D9) FAIL-CLOSED MOUNT INVARIANT**: an envelope volume whose
  `mxfs_v5_dlm_init` returns NULL must FAIL the mount (`xfs_super.c` →
  -ENOTCONN, `goto out_filestream_unmount`). The old "continuing single-node"
  fallback mounted BOTH test nodes uncoordinated on one LUN when PR-register
  aborted DLM init. Never restore the fallback; single-node use = DLM init
  succeeding as a 1-node cluster.
- **v0.11.78 (D7 CLOSED)**: the 4.7-20s joiner EX stall was the sess39/45
  wall-clock membership-settle gate (`memb_settle_ms=20000`) riding every
  membership change — it froze EVERY node's EX for up to 20s. Fix: lease UDP
  beacon (500ms) carries a FNV-1a-64 **view signature** (sorted member ids +
  count; `mxfs_lease_udp_msg.view_count/view_hash`, old-length packets remain
  valid beacons sans report). `dlm_view_confirmed()` (dlm.c) settles the gate
  as soon as every active peer reports MY exact signature received after MY
  last change. Wall-clock window is the fallback — behavior identical when
  proof is absent. Join wall 20.1s → 0.66s. APIs:
  `mxfs_dlm_get_view_sig/report_peer_view` (dlm.h),
  `mxfs_lease_set_view_provider/report_cb` (lease.h), glue in v5_mount.c TCP
  branch. Probe `P-D7-SETTLEGATE` stays in-tree.
- **v0.11.79 (D6 CLOSED) GOODBYE PROTOCOL**: `mxfs_v5_dlm_shutdown` broadcasts
  `MXFS_MSG_NODE_LEAVE` (after release_all + journal-slot release, before
  peer_shutdown, only when `!ctx->withdrawn`). RX clears the tcp_suspect
  entry, purges, lease-unregisters, and **refreshes active nodes** (P-GOODBYE-RX);
  the disconnect cb skips suspect/EX-freeze for nodes no longer in the lease
  (`mxfs_lease_has_node`) — "closed after clean departure — no death grace".
  Survivor EX work after peer clean-umount: 38s → 10ms. Fenced/withdrawn nodes
  never send goodbye (peers must recover their slice).
- **v0.11.80 (D4/D8) PR FENCE PROGRAM**: v5 never PR-preempted dead nodes at
  all (legacy mount.c blind preempts are user-mode only). Now both death paths
  (`v5_lease_expire_cb`, `v5_tcp_declare_dead`) call
  `v5_pr_fence_dead_node` FIRST (fence before purge/remaster/slice-replay):
  `mxfs_scsipr_fence_node(ctx, victim, live_members)` does READ KEYS
  classification — preempt only PRESENT victim keys; **topology guard**
  (count<live ⇒ P-PR-ADVISORY, no preempt/self-fence — shared-I_T-nexus rigs
  like the tcm_loop VM rig hold ONE registration for ALL VMs, each register
  overwrites the last); own-key-gone self-fence (-ESTALE → fence_notify)
  only when unambiguous (count>=live && live>=2). `registered` flag makes
  destroy's safety-net unregister idempotent (double-PROUT gone).
  D8: `mxfs_scsipr_probe` after register+reserve (both branches) logs
  per-node-PR usability at mount (P-PR-PROBE); periodic self-check in the TCP
  death worker (30s) → P-PR-ADVISORY latch / P-PR-SELFFENCE. Pending on
  sane-nexus rigs (cawd/QNAP): positive preempt + real ESTALE execution.

## v0.11.92 — orphan-grant NAK: membership-purge zombie heal (ccloop c7ee71c6 sess6, 2026-07-25)

**Defect (live-captured, TCP)**: `mxfs_dlm_update_active_nodes` (dlm.c)
purges the ENTIRE local lock table on EVERY membership change, and nodes
process membership events at different times during the mount ramp.  A
node's own GRANTED record can be purged locally while the (settled)
master's record survives.  The holder's later release then hits local
`-ENOENT` in `mxfs_dlm_unlock_gen` and — before this fix — sent NOTHING:
the master's zombie GRANTED entry starved the whole cluster (test6 AG-9:
`P5U-AGUNLOCK-ENOENT` at 17:28:15; master test2 re-BASTed 1/s for 500+s,
`P12-AGBAST-RX holders=0 cached=0 schedule=0`; test1's rm-rf blocked in
`mxfs_trans_preacquire_inode_ags` HOLDING the dir ILOCK → P132 →
3/3 runs DNF as SYSCALL_HANG/ABORTED_BY_PEER).

**New public API**:
- `mxfs_dlm_release_orphan_if_unheld(ctx, resource)` (dlm.c, decl dlm.h):
  guarded NAK — scans the bucket for ANY-state local-owner entry
  (GRANTED/CONVERTING/WAITING incl. in-flight `pend_waiter`); if one
  exists returns `-EBUSY` (never releases under a live local tenure or
  in-flight acquire), else sends the FIX-20b unconditional (gen=0)
  `LOCK_RELEASE` to the resource's current master.
- `mxfs_v5_dlm_ag_orphan_nak(ctx, agno)` (v5_mount.c, decl v5_mount.h):
  AG wrapper; TCP engine only (`ctx->dlm`) — CAW's on-disk slot is the
  single truth, no remote master table to diverge.

**Wire points**:
- `mxfs_dlm_unlock_gen` ENOENT branch (AG type): sets `ag_orphan_nak`,
  sends after `table_rwlock` drops, prints `P5N-AG-ORPHAN-NAK
  src=unlock-enoent rc=%d`, still returns -ENOENT.
- `mxfs_dlm_ag_bast_notify` (xfs_mxfs_dlm.c): unheld shape
  (`holders==0 && !cached && !bast_scheduled` && bast pending >3s) →
  NAK outside `pag_dlm_lock`, `P5N ... src=bast-rx`.  Self-limiting:
  fires once per incoming bast (~1/s) and stops when the master drops
  the zombie.

**Decode notes**: P12-AGBAST-RX's `page_ms` = ms since bast first went
pending (NOT paging); its `holder=` pid/comm is the stale LAST holder.
`schedule=` requires `cached=1` — `cached=0 holders=0` + old pending is
the zombie signature.

**Open (deferred, unobserved)**: the REVERSE purge arm — master's record
purged while the holder keeps its fs-layer grant → possible concurrent
EX after the 20s settle freeze.  Must be reasoned/instrumented before
any production verdict.  P5N/P5U counters are the standing harvest.

## sess10 (ccloop c7ee71c6, 2026-07-26, v0.11.104-108) delta
- v5_mount.c mxfs_v5_dlm_recovery_complete: both silent early-returns now print
  (P163-COMPLETE-BAIL / P163-COMPLETE-NOPEND) — permanent sentinels after the frankenstein
  NFS-module incident (see sess10-B memory).

## sess11 (ccloop c7ee71c6, 2026-07-26, v0.11.109-111) delta
- **Post-death membership (withdraw@2 fix)**: lease membership drives TCP mastership
  (`mxfs_dlm_resource_master` = active_nodes[hash%count]; active_nodes ⇐
  `mxfs_lease_get_active_nodes` = ACTIVE|JOINING entries). The P163 recovery path now
  calls `mxfs_lease_unregister_node(dead)` in BOTH `mxfs_v5_dlm_recovery_complete`
  (elected replayer) and `v5_recovered_cb` (deferred survivors), immediately before
  their `v5_refresh_active_nodes`. Do NOT unregister earlier (fence time): mastership
  must stay ON the dead node until its journal slice is replayed (sess9-D2 freeze).
- **P164 dead-identity set** (`mxfs_v5_dlm.dead_nodes[32]` ring): noted at fence
  (v5_lease_expire_cb), v5_tcp_declare_dead, GOODBYE. `v5_discovery_peer_cb` and
  `v5_peer_connect_cb_tcp` reject retired ids (P164-DEAD-REJECT) — a force-shutdown
  zombie keeps announcing/renewing until unmounted and must never re-enter membership.
  `v5_refresh_active_nodes` deliberately does NOT filter on the dead set (comment in
  code): filtering there would remaster at fence time and re-open the torn window.
- Victim side: `mxfs_v5_dlm_shutdown_withdraw` now also runs `mxfs_discovery_stop`
  (announce silence). Lease renewals intentionally KEEP running until unmount — they
  hold the entry ACTIVE so mastership stays frozen until the complete-unregister;
  post-unregister they're ignored (lease.c unknown-node print, now ratelimited).
- Print-level trap: "lease: unregistered node" is DEBUG (invisible in dmesg);
  P163-RECOVERY-COMPLETE prints AFTER a multi-second disklock_purge_node zeroing pass;
  the "peer joined — flushing" lines during recovery are the foreign-replay worker
  reusing mxfs_dlm_peer_joined_flush (NOT a membership join).

## TCP peer-connection lifecycle & the false-death class (sess12, v0.11.114)
- **Connection heal paths are asymmetric by construction**: `v5_discovery_peer_cb`
  (dlm/v5_mount.c) re-connects a lease-known-but-disconnected peer on EVERY ~500ms
  announce (lower-id → `mxfs_peer_connect`, higher-id → `_connect_force`). The peer
  layer (dlm/peer.c) resolves duplicate/simultaneous connections by REPLACING in the
  accept path — a join-storm flap where the two sides keep different sockets is normal.
- **connect_cb MUST fire on BOTH connect directions.** Historic defect: only the
  accept (inbound) path fired `ctx->connect_cb`; an outbound reconnect success left
  the v5 suspect timer armed → `v5_tcp_death_worker_fn` declared a peer with a live
  ESTAB socket dead after 40s → `v5_tcp_declare_dead` → whole-table purge (phantom
  grants at surviving masters) + P164 permanent exile of a LIVE node + membership
  fork (15 vs 16) → divergent hash-mastership → FIX-20b reconcile releases routed to
  the wrong master (silent rc=0) → root-ino EX starved → cluster-wide rc=-110.
  Fixed in `peer_connect_impl` (fires connect_cb after start_recv_thread) + a
  death-worker belt: cancel any suspect whose `mxfs_peer_is_connected()` is ACTIVE.
- **Debug affordances**: `ss -tn | grep :7600` on a node is ground truth for the peer
  mesh vs the DLM's beliefs; deterministic flap repro = `ss -K dst <peer> dport/sport
  = 7600` (both sides must print "deferring death" then "connected + cancelling
  pending death" within ~1s; the lower-id side heals OUTBOUND).
- ctx->peer / suspect table / death worker exist ONLY under
  `MXFS_V5_TRANSPORT_TCP` (v5_mount.c:1339) — CAW transports have no TCP mesh, so
  peer.c changes cannot regress CAW conditions.

## sess32 (session 14) — slot-claim provenance
- Both disklock claim variants (CAW + non-CAW) record `ctx->slice_adopted`:
  pass-1 own-stamp reclaim = false (full mount recovery required/safe),
  pass-2 fresh claim = true (inherited slice may be an already-recovered
  incarnation's; mount recovery suppresses its images). Exposed via
  `mxfs_disklock_slice_adopted()` → `mxfs_v5_dlm_slice_adopted()` →
  `mp->m_mxfs_slice_adopted`. Claim log prints which pass won.

## sess37 (ccloop c7ee71c6, 2026-08-01, 0.11.314-315) delta — DIRECT GRANT HANDOFF

### dlm_caw.c — release-CAS ownership transfer (knob mxfs.caw_direct_handoff=1)
- `mxfs_dlm_caw_unlock_gen` yield block: when releaser is LAST holder and fair-handoff
  picks EX waiter W → same CAS sets holders_ex|=W, clears W's waiter bits, yield_to=0,
  dir_epoch++ if last_ex_slot!=W, last_ex_slot=W, streak_note(EX). P6H-HANDOFF.
  Streak-yield arm batch-grants the whole PR class (holders_pr|=pr_w, streak reset
  in-CAS). P6H-PRBATCH. Nudge (`caw_send_grant_mcast`) targets ONLY the handed-off
  bits (p6h_handoff_bit) — an EX grant makes nobody else grantable.
- `caw_wait_for_grant` gained `reg_gen` param (generation the caller's registration
  CAS wrote — threaded from both call sites) + ADOPT branch before the self-stale
  check: adopt iff gen>reg_gen && own waiter bit CLEARED && holder bit set in the
  REQUESTED mode. ad_handoff := (cached grant_meta dir_epoch != slot dir_epoch)
  via new `caw_grant_meta_get_epoch`; no cache ⇒ true (safe). Also heals
  ambiguous own CAW (landed but reported -EAGAIN) — the sess34 untracked-wire-grant
  class. P6H-ADOPT.
- `caw_drop_own_waiter(ctx, slot_idx, giveup_mode)`: abort reconcile — the cleanup
  CAS also clears own holder bit of the ABANDONED mode (covers handoff-landed-mid-
  abort; P6H-ABORT-RECONCILE). Callers pass mode/new_mode. Upgraders keeping their
  old mode are untouched (only the abandoned mode's bit).
- Ownership-incarnation rules (GPT consult): stale pre-registration self-bits can't
  satisfy adopt (waiter bit still set → routes to P-SELF-STALE-EDEADLK as before);
  free boundary = EX exclusion; dead node = lease purge.
- A/B (same build, 32/caw, caw_grant_wait_anatomy 8 32): ON 11.1s total wait/max
  255ms vs OFF 95.8s/max 2657ms. Creates mean 109 vs 235ms.

## sess38 (0.11.321-322) — tail census + PR batch-claim
- P139-TAILCENSUS (in `caw_wait_for_grant`, unconditional >800ms, INODE only):
  per-wait counters bit_lost/chosen/foreign_yt/free_defer/doze250 + caw stats.
  P139-LOCKTOTAL (in `mxfs_dlm_caw_lock` at out:, >800ms): whole-acquire clock +
  per-CAS-site ea_* census — catches multi-retry and ADOPT-exit waits the
  per-wait census misses (adoption bypasses the promote-site emission).
- BATCH-COMPLETION-ON-CLAIM (promote CAS in caw_wait_for_grant): a PR claimer
  named by yield_to admits ALL still-registered shared-class ticket siblings in
  the same CAS (holders_pr|=sibs, waiters&=~sibs, yield_to=0). P6H-PRCLAIMBATCH.
  Kills the measured 9-node ~900ms one-CAS-at-a-time admission storms.
- Release-side P6H-PRBATCH guard relaxed: !slot_has_holders → no EXCLUSIVE-class
  holders (holders_ex|pw|cw); batch fires while sibling PR/CR holders remain.
- Turn economy at 32/caw dir_reuse (measured): inter-handoff p50=58ms p90=140ms;
  discovery (HANDOFF→ADOPT realms join) p50=2ms p99=40ms; grace idle tail 40ms
  (knob dir_ex_batch_grace_ms); remainder = holder work + Invariant-1 release
  drain (log_force SYNC + targeted AG drain, xfs_mxfs_dlm.c ~13600) — dominant.
  xfs_log_force_seq targeting was tried v0.3.38 and REVERTED (no effect + grant
  timeouts) — do not retry that shape.
- grace=10 A/B: cc 41→25s crash 79→21s BUT exposes
  D-AGI-UNLINKED-CROSSNODE-RECOVERY-SHUTDOWN (see ledger; default stays 40).

## sess38 late (0.11.324) — heartbeat outage anatomy
- disklock_hb_fn (dlm/disklock.c): per-cycle clocks — P-HB-SLOW (write_ms,
  lockwait_ms, age_since_last_ok_ms, prev monitor_ms; fires when write >2s or
  last-ok age >2 intervals) + P-HB-MONSLOW (monitor pass >2 intervals).  The
  hb write and the 32-peer monitor reads share ctx->lock through the one LUN;
  a saturated queue can stall the write past the 62s default lease
  (lease_timeout_ms=0 deployed) = the test21 self-fence
  (D-RELABORT-ORPHAN-LOOP-HEARTBEAT-SELFFENCE).  Probes unconditional,
  healthy-path silent.  hb failure log now carries age_since_last_ok_ms.
- sess38 FIX (0.11.325): the three disklock read loops (read_all;
  get_stale_slot_mask snapshot + poll) now take ctx->lock PER SLOT READ, not
  across the scan — the whole-scan hold starved the hb writer 26.7s live
  (P-HB-SLOW lockwait_ms=26726) and was the self-fence root.  INVARIANT: never
  hold ctx->lock across a multi-slot I/O loop; slot reads are 512B
  device-atomic.  D-RELABORT-...-SELFFENCE FIXED AND VERIFIED (ledger).


## sess43 (2026-08-02, v0.11.353) — recovery GUARD + lease-timeout semantics

### New HB record flag: `MXFS_DISKLOCK_FLAG_RECOVERY_GUARD` (=3)
An UNCLAIMED slot's AGI unlinked bucket can hold durable zombies with no owner
to reap them (an offline `chk_mxfs -y` repair lands on bucket `agino%64`; a
survivor can die after its sweep retired the dead slot; a shrinking cluster
never re-claims old slots).  The node sweeping such a bucket must hold a
CLUSTER-VISIBLE exclusion against a joiner claiming that slot mid-sweep —
inode-EX alone is not an ownership proof (GPT ruling: bucket removal also
mutates the AGI head / predecessor inode, and competing recovery authorities
could duplicate deferred-reap work).

- `mxfs_disklock_guard_slot/guard_refresh/unguard/slot_unclaimed` (disklock.c),
  exposed to the FS layer as `mxfs_v5_dlm_guard_*` / `_slot_unclaimed` /
  `_local_slot`.  All transitions are CAS from the exact stored image, with a
  write+settle+FUA-readback fallback on non-CAW targets.
- Both `claim_slot` pass-2 scans (CAW and non-CAW) SKIP a fresh same-generation
  guard; a STALE guard (holder died; older than
  `MXFS_DISKLOCK_GUARD_STALE_MS` = dead_threshold × hb_interval) is claimable
  again, and the new claimant's own-bucket rescan re-drives the bucket, so
  takeover needs no monitor or fencing involvement.
- The monitor, join gate, vergate and membership all key on
  `flags == ACTIVE`, so GUARD records are invisible to them: no member-count
  change and no fence risk for the live holder.
- The CAS is also the ELECTION between concurrent scanners — no separate
  singleton protocol.

### Lease timeout is TEN MINUTES, and that is load-bearing
`MXFS_LEASE_TIMEOUT_DEFAULT_MS = 600000` with `MXFS_LEASE_SUSPECT_MISSES = 150`
(lease.h).  A node that dies and rejoins takes a NEW node_id, so peers keep the
dead identity ACTIVE in their lease table — and therefore in the
`MXFS-MEMBERSHIP active_count` beacon — for up to ten minutes after every
fault-injecting event.  This is correct, self-healing behaviour, NOT a ghost
member: measured at 32/caw after crash_consistency, the beacon read 33 while
the on-disk heartbeat table held exactly 32 correct live writers (their
node_ids diffed 1:1 against all 32 nodes), and the beacon returned to 32 on
schedule.

**Consequence for any consumer of `active_count`:** never gate on
`active_count == N` over a window shorter than the lease timeout.  The
authoritative membership is the on-disk HB table (see
`tests/hb_live_count.sh`); `run.sh`'s reconvergence gate was fixed in sess43 to
consult it whenever a beacon over-counts.  Note `mxfs_lease_get_active_nodes`
counts ACTIVE **and** JOINING, and the expiry scan skips any entry whose
`last_renewal == 0` (lease.c:225) — an entry inserted without a renewal stamp
would never age out; every current insertion path does stamp it.


## sess44 (2026-08-02) — guard fencing facts (cite, don't re-derive)

- guard refresh (mxfs_disklock_guard_refresh) and unguard are FULL-512B
  owner-image CAS: any concurrent change fails them.  Refresh failure logs
  P99-GUARD-LOST, sets guard_slot=-1, returns -ESTALE — the UBSWEEP loop then
  sweeps nothing (per-AG refresh gate).  Unguard CAS failure logs
  P99-UNGUARD-RACED and leaves the successor's guard untouched.
- Refresh timestamps are FORCED monotonic (+1 floor) so identical successive
  stamps are impossible; ABA excluded by full-image compare + epoch/fs_gen +
  in-memory-only guard_slot (a rebooted holder cannot resume a guard).
- Refresh runs IN the sweeping thread between AGs — no independent timer — so
  a wedged sweeper's guard FREEZES and peers take it over (hb_guard_abandoned
  change-detection probe, 3x1000ms).  Verified live by guard_race_arms
  stale_resume/abandoned.
- mxfs_survivor_sweep_bucket_ag is READ-AND-ENQUEUE only; every destructive
  step revalidates on fresh iget under EX + AG-DLM (P19 B1-B5 gates), so
  concurrent double-drive of a bucket is safe by construction.
- C7 join gate: P-VERGATE-JOIN (disklock.c ~1440) — a joiner that finds a
  LIVE protocol-incompatible incumbent (feature-state + timestamp/epoch
  movement) refuses and withdraws.  Old-binary-refuses-new-fs still needs a
  superblock INCOMPAT bit (GPT sess44).

## sess93 (2026-08-04, 0.11.422-424) — THE FENCE-EVIDENCE CHANNEL IS WIRED

Until 0.11.422 the entire fence-certificate subsystem built in sess74/75/76 had
**zero callers** (proven by exhaustive grep, sess91). It had an on-disk wire
format, a `MXFS_PROTO_GEN` bump, and seven entry points, and none of them ever
ran. This is the change that connected it.

### The shape of the protocol (read this before touching recovery)

```
peer death (every survivor, heartbeat-monitor thread)
  v5_pr_fence_prove(node, slot, epoch)            dlm/v5_mount.c
      fence_intent()        durable BEFORE the P&A     -> stage FENCING
      mxfs_scsipr_fence_node()  PREEMPT AND ABORT
      fence_certify()       -> stage FENCED, UNOWNED, certificate written
  v5_start_slice_recovery -> elect -> XFS replay hook

elected replayer (foreign-replay workqueue / mount thread — NEVER the HB thread)
  mxfs_v5_dlm_recovery_acquire(slot)              dlm/v5_mount.c
      recovery_claim()      certified + unowned -> execution lease, auth parked
                            in ctx->recov_auth[slot] and HELD across the replay
      -EBUSY + owner proved dead  -> recovery_takeover()      (resume from stage)
      -EPERM + prover proved dead -> recovery_fence_takeover() + re-prove
      v5_exclusion_recheck()  the exclusion must STILL hold
  replay
  mxfs_v5_dlm_recovery_complete()  gate again -> advance -> purge -> zero
```

### Rules that are not negotiable

1. **ONE durable intent, ONE issuing prover, ONE command result, ONE possible
   certificate.** A node that does not win the intent CAS issues NO PREEMPT AND
   ABORT. Letting all 31 survivors fence (which is what shipped before) is
   unsound, not merely wasteful: a loser can remove the key before the intent
   owner issues its command, the owner then observes `KEY_ABSENT_UNPROVEN`, and
   the loser that actually got `PREEMPT_ABORT_DONE` is forbidden to certify.
   That converts a provable fence into an unrecoverable one.
2. **`mxfs_disklock_recovery_begin()` is RETIRED** — it refuses at entry with
   `P238-RECOV-BEGIN-RETIRED` / `-EPROTO`. It minted `FENCED` with
   `fence_kind = NONE`, i.e. the uncertified descriptor every gate must refuse.
   Do not resurrect it as a fallback.
3. **The gate sits below the dispatcher.** Both replay dispatch sites
   (`mxfs_dlm_foreign_replay_work_fn` and the mount barrier's inline round) and
   the completion path all ask. A dispatcher-only check lets a future caller
   recreate the defect.
4. **Claim ONCE and hold the auth** across replay and completion. Re-claiming
   per step makes ownership ambiguous and hides a takeover that happened while
   you worked.
5. **`-EPERM` from `recovery_acquire` is a WAIT state, not a failure.** There is
   deliberately NO timeout after which an unproven slice becomes replayable.
6. **A detector with `victim_epoch == 0` is not a fencing authority.** The
   lease-only path fences nothing and marks nothing pending — an epoch-0 pending
   marker would make `v5_start_slice_recovery`'s is-pending guard swallow the
   heartbeat monitor's later REAL detection, and only that one can certify.
7. **`recovery_takeover` and `recovery_fence_takeover` sleep
   `MXFS_RECOV_ABANDON_MS`.** Never call `mxfs_v5_dlm_recovery_acquire` from the
   heartbeat-monitor thread.

### What a certificate does and does NOT prove — MEASURED

`tests/pr_reregister_probe.sh` measured, at the SCSI layer: a
PREEMPT-AND-ABORTed node's write is REFUSED (exclusion is real at that instant),
and then the same node `REGISTER_AND_IGNORE`s a fresh key and writes
SUCCESSFULLY. So the certificate is **evidence of a completed eviction event,
not evidence that the host remains fenced**. For the ~8 s of in-place replay it
authorises, the only thing keeping a fenced-but-running victim off the LUN is
that victim's own cooperative self-fence.

`mxfs_scsipr_exclusion_holds()` (0.11.424) re-checks reservation health and key
absence at four points and stops the recovery when it has lapsed
(`P239-EXCL-RETURNED` / `P239-EXCL-LAPSED`). It is a **detector**: it cannot
prevent a write that races it. The enforcement gap is tracked as
`D-FENCED-VICTIM-MAY-REREGISTER`; the ruled options are a temporary
single-holder WRITE EXCLUSIVE gate (needs a cluster-wide freeze/drain protocol
MXFS does not have) or target/fabric revocation (outside a kernel module).

### New symbols

| symbol | file | what |
|---|---|---|
| `v5_pr_fence_prove` | v5_mount.c | the PROVER: intent -> P&A -> certify. 0 = a certificate exists, >0 = none (routes to settle residue), <0 = hard stop |
| `mxfs_v5_dlm_recovery_acquire` / `_release` | v5_mount.c | the gate + execution lease |
| `v5_exclusion_recheck` | v5_mount.c | is the exclusion still true? |
| `mxfs_scsipr_exclusion_holds` | scsipr.c | READ RESERVATION + READ KEYS re-check |
| `mxfs_disklock_recovery_slot_status` | disklock.c | read-only classifier: CONSUMABLE / SUPERSEDED / UNFENCED / FOREIGN / DESCRIPTOR / UNREADABLE. `recovery_claim` collapses these into `-ENOENT` and the correct response differs completely between them |

### Probes (all in `tests/`, all re-usable)

`fence_evidence_probe.sh` (one prover / one certificate / consumed by a
different node), `recov_takeover_doublefault_probe.sh` (kill the victim, catch
the owner claiming, kill the owner), `pr_reregister_probe.sh` (does a fenced
victim get back in?), `excl_lapse_probe.sh` (does a returned victim stop the
recovery?).

**Rig technique worth reusing:** the SCST backing store `/home/steve/disk.img`
can be read from clyde with `O_DIRECT` and is COHERENT with the live cluster
(verified: a live node's heartbeat sector changes across a 1.5 s host-side
reread). Superblock at 0, disklock table offset at `sb+64`, slot record =
`dloff + slot*512`; in the record `magic(0) flags(4) node_id(8)`, descriptor at
40, so `desc.stage` at 46 and `desc.owner_node` at 84. `RECOVERY_GUARD` = 3,
`FENCED` = 2. This gives a sub-millisecond vantage point for anything
timing-critical — the takeover probe needs `virsh destroy` in the SAME PROCESS
as the detection, because the window is ~8 s and an ssh round trip loses it.

**Do NOT identify a node from the `claimed heartbeat slot` dmesg line alone.**
It is a boot-time line and dmesg retention varies ~60x across nodes; the
longest-lived node (usually slot 0) has rotated it out. Close the map from the
platter instead — every ACTIVE heartbeat record carries its owner's node id.

### 0.11.425 — `RECOVERY_BLOCKED_FENCE`, the observable state

`/sys/kernel/debug/mxfs/<dev>/recovery_blocked`. Empty means nothing is
blocked. Populated, it names the victim (node / incarnation / key / slot), the
last fence kind + reservation type + PR generation, who holds the fencing
attempt and who holds the execution lease, how long the slice has been
unrecoverable, how many attempts, and an ACTION line per reason.

Ten reasons: `NO_PR`, `FENCE_UNPROVEN`, `CERT_UNRECORDED`, `NO_INTENT`,
`NO_CERTIFICATE`, `OWNED_ELSEWHERE`, `EXCL_LAPSED`, `SELF_FENCED`,
`NO_INCARNATION`.

**Layering:** the record and its accessor (`mxfs_v5_dlm_blocked_iter`, filling a
caller-provided `struct mxfs_recov_blocked`) live in `dlm/`; the debugfs file
lives in `xfs/xfs_mxfs_dlm.c`. That split is architectural invariant 4 — `dlm/`
must still build user-mode, so no `linux/debugfs.h` may appear there.

`first_ms` is stamped ONCE and kept. How long a slice has been unrecoverable is
the number an operator acts on; restamping it on every retry would hide exactly
that. `attempts` counts retries and is what separates a transient from a wedge.

### 0.11.426 — `dead_timeout_ms`, and zero-incarnation descriptors forbidden

**The module parameter `lease_timeout_ms` never configured the lease.** It fed
`mxfs_disklock_set_dead_timeout_ms()` and nothing else; the lease's own timeout
is `MXFS_LEASE_TIMEOUT_DEFAULT_MS` (600000, lease.h) and nothing ever writes it.
Canonical name is now `dead_timeout_ms`; `lease_timeout_ms` still works as a
deprecated alias (`dead_timeout_ms` wins if both are set) and logs the
correction at load. **The lease deliberately does not track it** — see the
sess43 section above on why ten minutes is load-bearing.

**`fence_intent()` refuses `!inc_valid(cur->epoch)`** (`P238-FENCE-ZEROINC`).
With `recovery_begin` retired, those are the only two writers of
`desc.victim_epoch` in the tree, so a zero-incarnation descriptor is now
unconstructible rather than merely unlikely — the sess91 ruling's "forbid them
at CREATION" option.

Note for anyone injecting an epoch into a heartbeat record: `hb_feature_crc()`
covers `fs_gen`, `node_id` AND `epoch`, so a naive epoch rewrite makes
`hb_feature_state()` read !OK and a *different* refusal arm fires. Reseal the
feature block or you measure the wrong thing.

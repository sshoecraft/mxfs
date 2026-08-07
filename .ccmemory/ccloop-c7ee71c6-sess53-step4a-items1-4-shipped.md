---
name: ccloop-c7ee71c6-sess53-step4a-items1-4-shipped
description: sess53: step-4a items 1-4 SHIPPED (adopt-CAS, KEEP_EX mount reclaim, deferred stale mask, mount_settle). Items 5-6 (xfs barrier + call site) remain.
metadata:
  type: reference
tags: [foreign-replay, D-FOREIGN-REPLAY, step4a, dlm_caw, v5_mount, adopt-window, settle]
---

# sess53 — step-4a items 1-4 shipped, build clean

Continues [[ccloop-c7ee71c6-sess52-GPT-ruling-adopt-window-and-settle-race]]
(that memory's "Remaining edit list for 0.11.399" is the checklist).
Campaign: [[compiled-foreign-replay-authority-tokens]].

Tree still says VERSION 0.11.398 — **rev to 0.11.399 when items 5-6 land**,
since only then does behaviour actually change.

## Shipped this session (items 1-4 of 6)

### 1. `dlm/dlm_caw.{c,h}` — adopt-CAS + hardened tracking
- `caw_adopt_retained()` (after `is_tracked_held`): in the adopt window,
  an untracked-but-ours bit is claimed with a REAL CAS (gen++,
  `last_modified_ms`), then tracked. `ex_grant_epoch` NOT restamped
  (GPT item 8). Returns 0 / -EAGAIN / errno.
- Wired into BOTH `mxfs_dlm_caw_lock` fast paths — `our_mode == mode`
  and `our_mode >= mode` — immediately before
  `caw_grant_meta_store_unless_releasing`. `-EAGAIN` → `ea_adopt++` +
  `continue`.
- `track_held()` now returns `bool` and latches `ctx->held_overflow`
  (new sticky field) + logs `P226-HELD-OVERFLOW` when the table is full.
- `mxfs_dlm_caw_purge_dead_nodes_ex()` **refuses with -EOVERFLOW** when
  `skip_tracked && ctx->held_overflow` (`P226-PURGE-REFUSED`).
  This is the resolution of GPT item 1: instead of failing the
  acquisition (which would abort a mount-time AG acquire and kill
  recovery), an unrecorded grant permanently disables the only consumer
  of "tracked" — so a live hold can never be purged. Fail-safe direction
  is asymmetric: leaking slots is recoverable, purging a live hold is not.
- Drive-by: HI divergence path now increments `div_hi` (was `div_lo`);
  `P-CAWEXH` dump gained `div_hi=` and `ea_adopt=`.

### 2. `dlm/v5_mount.c` step 4 — own-slot reclaim KEEPS the manifest
`mxfs_dlm_caw_purge_dead_nodes_ex(..., MXFS_CAW_PURGE_KEEP_EX)`, then
`set_adopt_window(true)` if `retained_count() > 0` (`P225-ADOPT-WINDOW`).

### 3. `dlm/v5_mount.c` step 6.5 — RECORD, don't purge
New ctx fields `mount_stale_mask` + `mount_stale_node[64]` (node id per
stale slot, captured via `mxfs_disklock_get_slot_node_id`). Logs
`P225-STALE-DEFERRED`. No purge on this path any more.

### 4. `dlm/v5_mount.{c,h}` — settle
- `v5_start_slice_recovery(ctx, slot, node)` factored verbatim out of
  `v5_lease_expire_cb`'s D2 tail (mark pending → elect → notify →
  re-election sweep). `v5_lease_expire_cb` now just calls it.
- `int mxfs_v5_dlm_mount_settle(struct mxfs_v5_dlm *ctx)` — 3 phases:
  1. own-slot `_ex(SKIP_TRACKED)`; -EOVERFLOW → `P226-SETTLE-DEGRADED`,
     log the leak, keep mounting.
  2. `set_adopt_window(false)` — **after** the purge, never before.
  3. per deferred stale slot: re-verify frozen over
     `dead_threshold * HB_INTERVAL_MS` (62 s default, early-exit poll)
     AND same node id still in the slot → `v5_pr_fence_dead_node` →
     `v5_note_dead_node` → `v5_start_slice_recovery`.
     Markers: `P225-SETTLE-VERIFY/-ALIVE/-REUSED/-RECOVER/-FENCEFAIL`.
     Grants are NOT reclaimed here — `mxfs_v5_dlm_recovery_complete`
     does that after the slice is actually replayed.

## Load-bearing finding: the monitor does NOT cover pre-existing stale slots

`check_dead` is gated on `nt->live` (disklock.c:748), and `nt->live` is
only set after `changed_samples >= MXFS_DISKLOCK_LIVE_THRESHOLD`
(disklock.c:688) — i.e. the monitor must first watch that heartbeat
**advance**. A slot already frozen when we mount never becomes live, so
the monitor never fires for it.

⇒ step 6.5's purge was the ONLY handler for previous-crashed-instance
locks, and it purged without replaying (the exact D2 violation sess9
fixed on the lease path). Deleting it without adding settle phase 3
would re-create the stuck-orphan mount deadlock 6.5's own comment
describes. Phase 3 is required, not belt-and-braces.

Also verified: `mxfs_disklock_get_stale_slot_mask` is a genuine
snapshot+wait+rescan with early exit, and its liveness test requires
`hb->node_id == snap_node[slot]`, so a slot re-claimed mid-window reads
as "not advanced" ⇒ **falsely stale**. That is why settle phase 3 has an
explicit identity gate against `mount_stale_node[]` before fencing —
without it the settle could hardware-fence a healthy new occupant.

## Remaining for 0.11.399 (items 5-6, unchanged from sess52)

5. `xfs/xfs_mxfs_dlm.c`: `mxfs_dlm_mount_recovery_settle(mp)` — the
   `mxfs_dlm_peer_joined_flush`-style barrier (double `xfs_log_force`
   SYNC + `xfs_ail_push_all_sync` + `mxfs_blkdev_flush_epoch`) then call
   `mxfs_v5_dlm_mount_settle(mp->m_mxfs_dlm)`.
   The barrier is what makes GPT item 6 true — recovery durable BEFORE
   any manifest-destructive purge.
6. `pal/linux/xfs_super.c:3080-3086` — call it after
   `mxfs_dlm_cache_init(mp)` (registers `dead_node_notify`, without
   which settle phase 3 bails with `P225-SETTLE-NOREPLAY`) and before
   `mxfs_init_all_perag_data(mp)`.

Then: rev VERSION to 0.11.399, `MXFS_FORCE_PREP=1 ./run.sh 32 caw
prep_cluster`, and board. Until 5-6 land, runtime behaviour of the
mount path HAS changed (items 2-3 are live) but nothing closes the
window or reclaims — **do not board an intermediate tree**, items 5-6
are required for a coherent mount.

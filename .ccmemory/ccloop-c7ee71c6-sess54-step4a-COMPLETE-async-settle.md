---
name: ccloop-c7ee71c6-sess54-step4a-COMPLETE-async-settle
description: sess54: step-4a items 5-6 SHIPPED (0.11.399) + GPT-forced redesign of phase 3 — continuous cancellable dead-confirm, settle worker off the mount thre…
metadata:
  type: reference
tags: [foreign-replay, D-FOREIGN-REPLAY, step4a, v5_mount, disklock, settle, 0.11.399]
---

# sess54 — step-4a items 5-6 shipped, VERSION 0.11.399, build clean

Completes [[ccloop-c7ee71c6-sess53-step4a-items1-4-shipped]].
Campaign: [[compiled-foreign-replay-authority-tokens]].

## GPT RULE-5 review forced two corrections to sess53's design

I proposed moving settle phase 3 (the 62 s re-verify + fence) off the mount
thread. GPT approved the split but **refuted two mechanisms**:

1. **Chained short probes AND-ed together are NOT equivalent to one long
   window.** `mxfs_disklock_get_stale_slot_mask` re-baselines on every call,
   so an advance landing between call N's last poll and call N+1's baseline
   read is invisible to both — N never sees it, N+1 adopts it as its own
   baseline. A live-but-slow node can then be declared dead and **fenced**.
   My original "13 × 5 s chunks, AND the masks" plan had exactly this hole.
2. **A final node-id identity check cannot see A → inactive → A'.** Node ids
   are UUID-derived, so a rebooted host returns with the SAME id. Only the
   heartbeat **epoch** (mount incarnation) distinguishes them.
3. Durability barrier: "double `xfs_log_force`" alone is not a proof —
   recovery-generated async work (inodegc from iunlink processing) must be
   drained first.

## What shipped

### `dlm/disklock.{c,h}` — `mxfs_disklock_confirm_dead_mask()`
New continuous, cancellable detector, purpose-built to be safe to fence on:
- ONE baseline (ts + epoch + node id) per candidate, held for the whole
  window; samples every `MXFS_DISKLOCK_HB_INTERVAL_MS` against it. "Never
  advanced" therefore means never, continuously — no re-baselining.
- Identity re-checked **every sample**, not once at the end: closes the
  A → inactive → A' ABA.
- Drops a candidate (= does NOT confirm dead) on ANY of: ts advanced, node
  id changed, epoch changed, record no longer ACTIVE, fs_gen foreign, read
  failed. Every ambiguity resolves toward "leave it alone".
- `expect_node[]` rejects at baseline a slot that already changed hands.
- `cancel` polled between samples (≤2 s unmount latency); early-exits as
  soon as every candidate is disproved.

### `dlm/v5_mount.c` — settle split
- `mxfs_v5_dlm_mount_settle()` now does phases 1–2 only (own-slot
  SKIP_TRACKED reclaim, then close the adopt window — order still
  load-bearing) and spawns `v5_settle_worker_fn` when
  `mount_stale_mask != 0`. New ctx fields `settle_thread` +
  `volatile settle_stop`.
- `v5_settle_worker_fn` = phase 3: drop slots whose node id was unreadable
  at 6.5 (`P225-SETTLE-NOID` — cannot fence an unknown node) →
  `confirm_dead_mask` over `dead_threshold` samples → fence → note dead →
  `v5_start_slice_recovery`.
- **Cancellation is honoured only while waiting.** A cancel always yields
  `confirmed == 0`, so we can never fence after one; and once a slot is
  confirmed, fence → note → mark-pending runs contiguously even if unmount
  is in progress (GPT: stopping in between strands the slice's grants with
  no elected replayer).
- Join added in `mxfs_v5_dlm_shutdown` immediately after the tcp_death
  join — **verified** it precedes journal/lease/disklock/caw/peer/dlm/scsipr
  teardown, so every subsystem the worker touches is alive. `out_unmount`
  and `out_filestream_unmount` both reach that shutdown.

### `xfs/xfs_mxfs_dlm.{c,h}` — `mxfs_dlm_mount_recovery_settle(mp)`
Barrier = `xfs_inodegc_flush` → `xfs_log_force(SYNC)` →
`xfs_ail_push_all_sync` → `mxfs_blkdev_flush_epoch`, doubled with the
`msleep(20)` that covers the async `xlog_cil_committed` → AIL insertion
window. Quiescence here is *real*, not assumed: at this point `xfs_mountfs`
has returned (so `xfs_log_mount_finish` already did intent replay + iunlink
processing), `s_root` is not yet set so no VFS request can reach us, and the
only remaining old-incarnation work is the inodegc the iunlink processing
queued — hence the explicit flush.

### `pal/linux/xfs_super.c`
Called after `mxfs_dlm_cache_init(mp)` (registers the slice-replay hook)
and before `mxfs_init_all_perag_data(mp)`.

## Why async is not weaker (recorded so it isn't re-litigated)

Phase 3 only STARTS recovery (mark pending → elect → notify); the replay is
asynchronous in both arrangements, so a synchronous 62 s wait delays the
mount without shortening the unreplayed-slice exposure by one millisecond.
Access to whatever the dead peer held is gated by its unreclaimed CAW grants
for exactly as long either way — **verified**: nothing steals a grant on
timeout (acquire exhaustion returns an error and leaves the lock held), and
the only `purge_dead_nodes` callers are the two mount paths plus the
post-recovery death path. Cost of the sync form: +62 s on EVERY node's mount
on a cold restart after a whole-cluster crash (RULE 0).

## OPEN — verify before/while boarding 0.11.399

`mxfs_init_all_perag_data` is safe (raw `xfs_alloc_read_agf(pag, NULL, 0,
&bp)` — no transaction, no AG DLM lock), so the perag baseline cannot block
on a dead peer's retained bits.

**Unverified:** whether anything inside `xfs_mountfs` / `xlog_recover`
acquires an AG DLM lock. `__mxfs_ag_dlm_lock` (xfs_mxfs_dlm.c:34101) has NO
mount-phase or recovery-phase guard — `if (!dlm) return 0;` then straight to
the fast path and real CAW I/O. Step 6.5 used to purge the dead peers' bits
*before* `xfs_mountfs` ran; now it only records them, so if recovery does
take AG locks, a mount following a peer crash could park on the CAW poll.
This is the concrete shape of the "stuck-orphan mount deadlock" 6.5's own
comment warned about. Check this first — a mount hang would burn a whole
rig cycle.

Then: `MXFS_FORCE_PREP=1 ./run.sh 32 caw prep_cluster` and board.
Markers to grep: `P225-ADOPT-WINDOW`, `P225-STALE-DEFERRED`,
`P225-SETTLE-VERIFY/-ALIVE/-NOID/-RECOVER/-FENCEFAIL/-CANCELLED`,
`P226-SETTLE-DEGRADED`, `P226-PURGE-REFUSED`, `P226-HELD-OVERFLOW`.

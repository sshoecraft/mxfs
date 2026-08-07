---
name: ccloop-c7ee71c6-sess59-item1-and-6D-fixed-purge-honesty
description: sess59: GPT items 1 + 6D FIXED (0.11.403). Both purge functions were reporting success on incomplete purges — fixed, and publication now gates on the…
metadata:
  type: reference
tags: [foreign-replay, mount, recovery, durability, step4a, purge, in-progress]
---

# sess59 — GPT items 1 and 6D fixed

Build **0.11.403**, srcversion `A57E80734521469C86653B2`, compiles clean
(only the pre-existing `xfs_platform.h` iomap/bioset warnings).
**STILL DO NOT BOARD** — GPT items 6B, 3, 4, 2/5, 6C, 6H remain open.

## Item 1 — durability vs coherency (FIXED)

New `mxfs_blkdev_flush_durable(mp)` (xfs/xfs_mxfs_dlm.c, declared in the
header).  ALWAYS issues `blkdev_issue_flush` regardless of
`mxfs_fua_disable`, normalises `-EINVAL` (write-through device) to 0,
advances the epoch only on success, returns the failure, logs
`P228-FLUSH-DURABLE-FAIL`.  `mxfs_blkdev_flush_epoch` is untouched for
the per-modify callers — its fast path is a COHERENCY argument and a
per-op COST argument, neither of which covers a once-per-mount barrier
that needs the data to survive a TARGET power loss.

Wired in three places:
1. Barrier step (a): failure now ABORTS the mount (nothing has been
   published yet, so a clean failure is available).
2. Barrier step (c), post-replay per slice: failure keeps the slot OUT of
   `replayed`, so (d) never publishes it.  Its grants stay frozen and its
   pending marker stays set — replay is LSN-gated and idempotent, so the
   next mount redoing it is free.
3. **The LIVE foreign-replay path had the identical hole** and is the far
   more common one: `mxfs_dlm_foreign_replay_work_fn` bracketed the
   replay with `mxfs_dlm_peer_joined_flush`, which bottoms out in
   `mxfs_blkdev_flush_epoch` → NO device flush at all under the default
   `fua_disable=1`.  It then called `recovery_complete`, destroying both
   pieces of evidence that would make anyone redo the replay.

## Item 6D — publication gating (FIXED), and two purge-honesty defects

GPT asked for "CAW-purge or flush failure must block publication".
Neither purge function could report failure in the first place:

**`mxfs_dlm_caw_purge_dead_nodes_ex` (dlm/dlm_caw.c)** returned a
success-shaped count while silently swallowing: per-slot read failures in
the non-batch fallback, read failures inside the CAS retry loop,
non-EAGAIN `caw_slot` failures, and 20-retry EAGAIN exhaustion.  Added
`unread` / `wfail` accounting → `-EIO` + `P231-PURGE-INCOMPLETE`.  All
existing callers already guard on `npurged > 0` or `< 0`, so no call site
regressed; `mxfs_v5_dlm_settle_own_slot`'s comment ("the only failure
that reaches here is -EOVERFLOW") was corrected.

**`mxfs_disklock_purge_node` (dlm/disklock.c)** was worse: it swallowed
the **heartbeat-zero write failure**, which IS the cluster-wide "slice
replayed, run your deferred purges" broadcast, and returned "purged N"
so the caller logged `P163-RECOVERY-COMPLETE` with the dead node's HB
record still ACTIVE.  Also skipped unreadable lock-record sectors (any of
which could be an ACTIVE dead-owned grant) and counted them clean.  Now
tracks `rd_fail / wr_fail / hb_rd_fail / hb_wr_fail / hb_found` and
returns a negative errno + `P229-PURGE-INCOMPLETE` when the purge cannot
be proven complete.

**`mxfs_v5_dlm_recovery_complete`** is now `int` and ordered:
1. CAW purge — on failure STOP, publish nothing (`P230-COMPLETE-CAWFAIL`).
2. `mxfs_pal_bdev_flush(ctx->dev)` — the CAW purge must be on the platter
   BEFORE the broadcast.  Reverse order survives a power loss as "node
   gone, grants still held, no pending marker" = unrecoverable wedge;
   this order fails as "node still looks alive", which the death detector
   simply redoes (`P230-COMPLETE-FLUSHFAIL`).
3. disklock purge (the broadcast) — failure blocks publication
   (`P230-COMPLETE-PURGEFAIL`).
4. Only then clear the local pending marker + beacon.

**`mxfs_v5_dlm_mount_cohort_complete`** is now
`int (ctx, slots, uint64_t *out_published)` — per-slot failures don't
stop the others, it returns the first error and reports
`P230-COHORT-PARTIAL`.  The barrier fails the mount when
`published != replayed`, for the same reason step (b2) does: unpublished
slices' grants are still held by nodes that cannot release them, so
`xfs_log_mount_finish` would stall 120 s per acquire and fail anyway.

**Live path retry:** new duty bit `MXFS_REAPF_FREPLAY` (=2,
xfs/xfs_mount.h).  A failed flush or publication leaves the slot bit set
in `m_mxfs_foreign_dead_slots`, sets the duty and calls
`mxfs_reap_sched(MXFS_REAP_RETRY_MS)`; `mxfs_reap_worker` re-queues
`m_mxfs_foreign_replay_work` while any dead slot remains, and the
worker's existing tail (`mp->m_mxfs_reap_duties` non-zero) keeps
rescheduling.  So a transient device error retries every 30 s instead of
stranding the dead node's slice.

## Files touched

`xfs/xfs_mxfs_dlm.{c,h}`, `xfs/xfs_mount.h`, `dlm/dlm_caw.c`,
`dlm/disklock.c`, `dlm/v5_mount.{c,h}`.

## Next session order

1. Item 2/5 — `mxfs_dlm_invalidate_cached_views` must return
   complete/incomplete-busy/fatal and only clear `pag_dlm_cached` /
   `bast_pending` / `release_pending` / `lineage_open` on complete.  A
   preserved dirty/pinned/IN_AIL buffer means the old cached view still
   exists, so the AG must NOT be declared uncached.  Applies to
   `mxfs_dlm_peer_joined_flush` too.
2. Item 6B — a peer healthy at step 6.5 can freeze DURING the 62 s
   confirm window; its grants aren't in `mount_stale_mask`.
3. Items 3 and 4 — the publication-staging redesign (multi-stage durable
   state FENCED/IMAGES_REPLAYED/INTENTS_PENDING/CONSUMABLE) and the
   own-retained-bits purge-before-`xfs_log_mount_finish` safety proof.
   These two are the big ones.
4. Item 6C — per-slot `safe_to_publish` mask.  Partly satisfied already
   by the sess59 `published` mask + the per-slice durability gate;
   re-read GPT's requirement against what now exists before doing more.
5. Item 6H — cross-slice LSN comparability.  May be an independent open
   defect (cross-checks `compiled-foreign-replay-crash-consistency`'s
   "non-comparable per-node LSNs").
6. RULE-5 consult on the whole set before any rig cycle.

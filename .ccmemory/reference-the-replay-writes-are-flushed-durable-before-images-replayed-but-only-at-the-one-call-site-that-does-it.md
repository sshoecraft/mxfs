---
name: reference-the-replay-writes-are-flushed-durable-before-images-replayed-but-only-at-the-one-call-site-that-does-it
description: REFERENCE (s132): the foreign replay itself never flushes; mxfs_blkdev_flush_durable at the single completion caller is what orders it before IMAGES_…
metadata:
  type: reference
tags: [recovery, durability, fencing, foreign-replay]
---

# Where the replay-writes-before-IMAGES_REPLAYED ordering actually comes from

The fencing ruling's requirement D says durable ordering must be PROVEN:
replay writes before `IMAGES_REPLAYED`, purge before `GRANTS_RELEASED`,
everything before the sector zero — and "CAW atomicity does not imply cache
persistence across target power loss". Read end to end, s132:

- **The replay pass does not flush.** `xlog_do_recovery_pass` ends at
  `xfs_buf_delwri_submit(&buffer_list)` (`xfs/xfs_log_recover.c:6836`), which
  returns on COMPLETION, not durability. The only `blkdev_issue_flush` in that
  file is inside `mxfs_replay_cut_partial` (:6456) and exists solely so the
  crash-cut's prefix is genuinely on the platter. The normal path has none, and
  `mxfs_xlog_recover_foreign_slice` (`xfs/xfs_log.c:1017`) adds none before it
  prints "foreign replay of slot %u complete".
- **The milestone write does not order itself either.** `recov_cas_durable`
  (`dlm/disklock.c:6218`) does the CAW and THEN `mxfs_pal_bdev_flush`. `hb_caw`
  bottoms out in `mxfs_pal_bdev_compare_and_write`, and `caw_flush` defaults to
  0. So nothing in the CAS path puts a barrier BEFORE the milestone.
- **The ordering is enforced at the caller, and it is the only one.**
  `v5_recovery_complete_ladder` states the invariant in a comment
  (`dlm/v5_mount.c:14622` — "every caller flushes first"), and there is exactly
  one caller chain: `mxfs_v5_dlm_recovery_complete2` ← `xfs/xfs_mxfs_dlm.c:60543`.
  Immediately above it, `mxfs_blkdev_flush_durable(mp)` (:60512) runs and the
  completion is SKIPPED if it fails. Its comment records that this was found and
  fixed in sess59: the earlier `mxfs_dlm_peer_joined_flush` bottoms out in
  `mxfs_blkdev_flush_epoch()`, which under the default `mxfs_fua_disable`
  issues no device flush at all — it certifies peer VISIBILITY, not survival of
  a target power loss.

So the pair is ordered, by one call in one place, and the invariant is a comment
rather than anything the compiler or the API enforces. A second completion
caller added later would silently reintroduce the hole.

## The two `goto complete_ladder` shortcuts, and the one question left open

Both bypass that flush (`xfs/xfs_mxfs_dlm.c:60431`, `:60608`):

- **:60431** is safe by construction: it is taken only when the durable
  descriptor already reads `>= IMAGES_REPLAYED`, so this pass wrote nothing.
- **:60608** is the OPEN-obligation case, taken when `mxfs_recov_obl_complete(mp,
  slot)` returns 0. That path DOES discharge obligations (EFI work, real
  metadata), and it jumps straight to the ladder. **NOT YET READ: whether the
  `OBLIGATIONS_DONE` milestone (`mxfs_disklock_recovery_advance_obl_done`,
  `dlm/v5_mount.c:20552`, reached from `xfs/xfs_mxfs_recov_obl.c:331`) is
  advanced before those discharge writes are durable.** That is the same shape
  sess59 fixed one milestone earlier. The ladder's own flush
  (`dlm/v5_mount.c:15006`) sits before `GRANTS_RELEASED`, which is too late to
  order `OBLIGATIONS_DONE`.

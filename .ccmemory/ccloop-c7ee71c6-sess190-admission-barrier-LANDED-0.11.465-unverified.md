---
name: ccloop-c7ee71c6-sess190-admission-barrier-LANDED-0.11.465-unverified
description: sess190: admission barrier A+B+C LANDED, 0.11.465 sv 4DB2D8A8 builds clean; req D proven already-satisfied (fence_intent atomic CAS). NOT deployed/ve…
metadata:
  type: project
---

# sess190 — mount admission barrier landed (D-SHUTDOWN-UMOUNT-CLEAN-RELEASE-DIRTY-SLICE)

Tree 0.11.465, mxfs.ko srcversion 4DB2D8A8247E6DF80AE6F2F. Builds clean.
NOT deployed, NOT rig-verified.

## Ruling req D — RESOLVED BY VERIFICATION, no code change needed
`mxfs_disklock_recovery_fence_intent` (disklock.c ~3571) replaces the
victim's WITHDRAWN flags with MXFS_DISKLOCK_FLAG_RECOVERY_GUARD and lays
the full FENCING descriptor in ONE `recov_cas_durable` call (bdev
compare-and-write, or FUA write + 30ms + read-back verify on -EOPNOTSUPP,
then mxfs_pal_bdev_flush). So the durable requiring-recovery evidence is
never absent: a dirty slice is WITHDRAWN xor descriptor(stage>=FENCING)
at every instant. Consequence: the admission sweep must read ON-DISK
descriptors, never mxfs_disklock_recovery_is_pending (in-memory only,
sess189 finding confirmed).

## Landed (shapes A+B+C of sess189 ruling)
- disklock.c/.h: `mxfs_disklock_get_recovery_pending_slots(ctx, skip,
  &mask, node[], epoch[])` — pending = WITHDRAWN or desc stage <
  GRANTS_RELEASED; fail-closed bits (unread sector, recov_desc_present
  but !recov_desc_of) carry no identity.
- v5_mount.c/.h: `mxfs_v5_dlm_mount_pending_recovery` — sweep + arm
  pending_node/pending_epoch from on-disk victim identity (else
  recovery_acquire returns -ENODATA for peer-fenced slots); idempotent
  re-arm guard avoids P163 spam per poll.
- xfs_mxfs_dlm.c barrier: `for(;;)` — every pass drains mphase THEN
  sweeps; todo=(cohort|drained|pend)&~replayed; clean cut breaks; rounds
  1..4 inline replay (acquire rc==-EBUSY → xfs_notice, poll for owner);
  past rounds poll 1s to 30s (MXFS_BARRIER_ADMISSION_WAIT_MS, RULE-0
  derived) then ABORT mount -EBUSY with late deaths deferred back.
  Post-loop: (seen & ~replayed) → invalidate_cached_views else abort
  (peer-completed slices, stale cached images).

## Behavior changes to watch on the board
1. Unfenceable dead residue that carries a descriptor now FAILS the mount
   after 30s (previously proceeded if it owned no resources). Per ruling:
   round cap is not permission to go live with leftovers.
2. Every mount pays a 64-sector sweep per barrier pass (~ms) — no
   measurable mount-time cost expected; verify on the board.

## Pre-existing, not mine
disklock.c -Wframe-larger-than warning at mxfs_disklock_confirm_dead_mask
(1344B; function untouched, only line-shifted).

## Next
Deploy test32 → tests/dirty_slice_release_repro.sh test32 all (<60s).
PASS = marker survives remount. Then 32-node deploy + full board, then
Fix 2 Arm C (HB release after xfs_unmountfs), join interlock audit.

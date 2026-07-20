---
name: sess113_lessons
description: sess113 — cache_coherency drain-wedge ROOT NAMED via b_lock_ip tracking: leaked cluster-buf lock = merge_dirs forced-FUA read in xfsaild flush path.…
metadata:
  type: project
---

# sess113 (ccloop run 4eef1f39) — cache_coherency drain wedge ROOT NAMED + fix

## METHOD WIN: lock-holder tracking (Gemini RULE-5 instrumentation, KEEP)
Added `void *b_lock_ip` to struct xfs_buf (xfs/xfs_buf.h), set to
`__builtin_return_address(0)` in xfs_buf_lock()+xfs_buf_trylock() (pal/linux/xfs_buf.c),
cleared in xfs_buf_unlock(). Drain probe `P113-DRAIN-WEDGE` (xfs_mxfs_dlm.c
mxfs_ail_drain_inode_sync) prints `holder=%pS`. This NAMED the leaker in ONE repro
where 90 sessions of code-reading failed.

## PROVEN (RULE 4, live evidence, build 1F8B4DD1)
cache_coherency wedge = ino=128 (root dir) inode-cluster buffer LEAKED-LOCKED:
`lb_flags=0x20 (XBF_DONE only) lb_hold=4 lb_onlist=0 lb_locked=1 holder=xfs_inode_item_push+0x92`
STABLE across iter 256..4352. Inode IFLUSHING+in_ail+pin=0+ili_fields=0.
- `+0x92` disassembles to the instr right after `call xfs_buf_trylock` (line 771 of
  xfs_inode_item_push) => xfsaild's push trylocked it and it was never unlocked.
- NO thread holds it (no xfsaild in D-state, only the BAST kworker spinning in the
  drain msleep). scsi_eh threads present (SCSI errors being handled).
- State = post-iflush_cluster, pre-delwri_queue window: the ONLY blocking op there is
  `mxfs_iflush_cluster_merge_dirs(bp)` at END of xfs_iflush_cluster (xfs/xfs_inode.c
  ~4013), which does a SYNCHRONOUS forced SCSI FUA read (mxfs_pal_scsi_read_fua_bdev)
  while holding the cluster buf lock. merge_dirs is `void` (can't error-return), so
  Gemini's error-bubble theory is OUT — the mechanism is the FUA read stalling/erroring
  on the SCST target (fua_disable=1 default since sess94 exists precisely because
  forced-FUA reads misbehave here; merge_dirs bypassed that gate).

## FIX (build 5E2660AC, BUILT, NOT yet deployed/tested)
`mxfs_iflush_cluster_merge_dirs` now returns early `if (mxfs_fua_disable)` — when FUA
disabled, reads are coherent via shared cache so the FUA-overlay is unnecessary AND is
what wedges the flush. Added `extern int mxfs_fua_disable;` to xfs_mxfs_dlm.h.
Also: reverted my hard-hanging active-drain (see below); drain is back to PASSIVE +
the b_lock_ip probe.

## FAILED this session (RULE 4 step 2a, reverted)
ACTIVE own-the-flush drain (xfs_imap_to_bp+xfs_iflush_cluster+xfs_bwrite from the BAST
kworker, + drain_alloc_buflist every iter) — HARD-HANGED test1 (no ping/ssh/sysrq).
Gemini: xfs_bwrite on a buffer still carrying _XBF_DELWRI_Q corrupts XFS buf-list
invariants (fatal); drain_alloc_buflist=xfs_buf_delwri_submit in the loop compounds it.
DO NOT bwrite/force-unlock from the BAST kworker. Both sess112 force-unlock AND this =
hard hang. Passive drain only soft-wedges (debuggable).

## NEXT (RULE 4 step 2b — confirm the fix)
Clean reboot ALL 4 (virsh destroy+start, 70s), `bash tests/reset4.sh 4`, confirm
5E2660AC on all nodes, dmesg -C, run `tests/criteria/cache_coherency.sh --nodes 4`.
- If NO `P113-DRAIN-WEDGE` and cache_coherency passes more subtests -> merge_dirs FUA
  was the wedge. Then run full verify_ship.sh.
- If wedge persists, the P113-DRAIN-WEDGE `holder=` still names the leaker; if still
  xfs_inode_item_push, the leak is elsewhere in push/iflush/delwri/iodone on the SHARED
  cluster buf (xfsaild thread may be stuck in merge's SCSI read but hard to spot — dump
  ALL thread stacks incl S-state). Consider Gemini Option A (move merge BEFORE the
  IFLUSHING loop, return -EAGAIN on failure) or the GFS2-style demote-workqueue re-arch.
- reset4 needs clean reboot first (stale module rmmod-busy => RESET_FAIL otherwise).
- Marker NOT written — criterion FAILS.

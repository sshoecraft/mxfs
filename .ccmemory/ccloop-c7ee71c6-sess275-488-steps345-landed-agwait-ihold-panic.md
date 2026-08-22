---
name: ccloop-c7ee71c6-sess275-488-steps345-landed-agwait-ihold-panic
description: sess275: D-488 tri-state steps 3-5 LANDED 0.11.497 sv D4E2D159, strand-inject PASS 32/32; NEW PANIC: agwait handoff ihold/irele in evict context (tes…
metadata:
  type: project
---

# sess275 — D-488 fix complete + new panic found

## Landed (0.11.497 sv D4E2D1599373E6F5876F62D, deployed fleet-wide)
Steps 3-5 of sess273 ruling in xfs/xfs_mxfs_dlm.c:
- bast_work_fn tail switch: RELEASED normal; UNKNOWN→10×1s re-verify
  (P275-AGUNLK-REVERIFY); STILL_HELD→re-mint via mxfs_ag_dlm_lock +
  unlock, bast_pending re-set (P275-AGUNLK-REARM/-FAIL); final
  UNKNOWN→quarantine demoting=1 release_pending=1 no-wake
  (P275-AGUNLK-QUARANTINE).
- rx watchdog in bast_notify: sched latched >30s → requeue
  (P275-AG-STUCK-LATCH — FIRED FOR REAL on test6 ag=1 page_ms~50s
  during rsync run2, requeued); demoting >60s → P275-AG-DEMOTE-STUCK.
- Loud non-RELEASED at force_release_all/release_work_fn/iodone
  (P275-AGUNLK-{UNMOUNT,DEFERRED,IODONE}-NOTREL).

## Verification so far
- prep_cluster 32/caw OK 73s. ag_strand_repair PASS 32/32 (78s,
  strands repaired, 0 faults) — injected silent-strand recovery WORKS.
- rsync_paired run1 PASS 32/32 19s. Run2 FAIL NO_TERMINAL_RECORD=32:
  test5 KERNEL PANIC (barriers hung fleet-wide).

## NEW CRITICAL DEFECT (unledgered): agwait-handoff ihold in evict
test5 serial log (uptime 20505s): invalid opcode in iput+0x1c5, stack:
rsync rename → dput → evict → xfs_inactive → xfs_inactive_truncate →
xfs_bunmapi_range → xfs_defer_finish_noroll → mxfs_defer_agwait →
mxfs_trans_agwait_handoff+0x378 → xfs_irele → iput BUG. Taint W = an
earlier WARN (ihold's WARN_ON inc-from-0, consistent).

ROOT (code-read, xfs_mxfs_dlm.c 40849+40873): handoff pins handed-off
inodes with ihold(VFS_I(ip)) then xfs_irele after relock. In the
INACTIVATION path (evict) the joined inode has i_count==0 and
I_FREEING set: ihold 0→1 is a VFS violation (WARN), and xfs_irele
1→0 re-enters iput_final/evict on an inode already inside evict →
BUG_ON. The ihold/irele pair is unnecessary: every joined inode is
ILOCKed by the caller, whose reference/lifetime spans the whole
xfs_defer_finish call (for the inactive path, evict itself is the
lifetime). Candidate fix = drop ihold+xfs_irele entirely (or gate on
i_count, worse). RULE 5 consult before landing — this seam is
GPT-ruled territory (sess263/267/269 rulings).

Affects BOTH callers: mxfs_defer_agwait (SEAM) and
mxfs_trans_preacquire_inode_ags (PREACQ ~41159).

## Next
1. GPT consult on fix shape; land; rebuild 0.11.498; redeploy
   (prep_cluster again — test5 died mid-run, cluster state dirty).
2. Re-run 3× rsync_paired + 3× scaling_curve + board.
3. Ledger the new defect (D-AGWAIT-IHOLD-EVICT-PANIC-497 or similar)
   + update D-488 next-steps + ruling leg v check (#1/#5/#19).

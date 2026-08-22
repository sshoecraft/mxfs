---
name: ccloop-c7ee71c6-sess212-test6-iunlink-fossil-EUCLEAN-capture-477
description: sess212: rsync_paired lap3 on 0.11.477 — test6 EUCLEAN = xfs_iunlink_item_precommit fossil di_next_unlinked=0x81df6 (not NULLAGINO), shutdown+withdra…
metadata:
  type: project
---

# sess212 — decisive capture: rsync overwrite EUCLEAN = iunlink fossil

## Event (0.11.477 sv 79342FFAD37A8568EB0B033, 32/caw, rsync_paired lap 3)
- 17:49:51Z test6: "Metadata corruption detected at
  xfs_iunlink_item_precommit+0x1a6 [mxfs], inode 0x3681df8
  xfs_iunlink_log_dinode" → Corruption of in-memory data (0x8) at
  __xfs_trans_commit (xfs_trans.c:898) → shutdown → P-WITHDRAW-QUEUE.
- Userspace (sess202 stderr capture VERIFIED — lands in criteria.json 32/caw
  rsync_paired `reason`): rsync rename ".file1.zvY6Jw"→"d2/file1" failed
  "Structure needs cleaning (117)" (EUCLEAN); subsequent mkstemp EIO
  (post-shutdown). rc=23, files=0/400.
- Dinode hex decoded: v3, mode 100644, size 71, nlink=1, gen 0x8b028f2b,
  **di_next_unlinked @0x60 = 0x00081df6 (agino 532982), not NULLAGINO** —
  fossil unlinked-list pointer from a prior tenancy. Rename displaced the
  target inode onto the AGI unlinked list; precommit found the cluster-buf
  dinode already chained → EFSCORRUPTED.
- Context: P150-ALLOC agno=27 startino=534528 just before (same agino
  neighborhood). fs was fresh-prepped 17:29Z, aged ~20min by full board.
- Evidence: tests/evidence/rsync477_test6_iunlink/test6.klog.gz
  (17:47-17:55Z window) + criteria.json reason field.

## Classification
- Family = #30 D-AGI-UNLINKED-CROSSNODE-RECOVERY-SHUTDOWN (root PROVEN sess40
  by tests/agi_bucket_repro.sh — upstream in-core unlinked-list premises false
  cross-node; remaining increments: open-tracking coordinator (3), survivor
  sweep (2b), matrix) and the P53 fossil-di_next_unlinked campaign.
- #17 D-RSYNC-OVERWRITE-LAP-USERSPACE-FAIL-ERRNO-UNKNOWN: its ledgered mode
  was SILENT at the kernel (rc!=0, leftover dotfile, no probes, no shutdown).
  Today's is kernel-loud — do NOT merge without evidence; but #17 next-steps
  1-2 (verify stderr capture, read errno) are now DONE for the loud mode.

## Rig state at session end
- test6 down/withdrawn; 31 nodes up. rsync_paired recorded FAIL 31/32 at
  32/caw. Needs prep_cluster re-prep before next laps.
- Board on .477 was 27/27 real PASS before this (17:36-17:46Z).
- 0.11.477 change: fence-scoped ailstuck latch (probe=2 + armers refcount,
  disarm on fence success/min-advance, kept on DRAIN-STUCK/shutdown) — fixes
  9/32-node permanent-latch noise accumulation from benign stall bursts.

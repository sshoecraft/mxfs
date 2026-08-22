---
name: ccloop-c7ee71c6-sess340-513B-review-fixes-landed-0.12.6
description: sess340: RULE-5 review of 0.12.5 #91 fix = STOP-SHIP (5 items); all 5 fixed+built 0.12.6 sv FE2B7E1CF2A875536F20577 — NOT deployed; next = re-prep +…
metadata:
  type: project
tags: [d-513, foreign-replay, rule-5, stop-ship, review]
---

# sess340 — 513B RULE-5 review STOP-SHIP + all fixes landed (0.12.6)

## Review verdict (GPT, on the sess339 0.12.5 landing)
STOP-SHIP, 5 required items. Ratified: adopted-slice keeps upstream shutdown
(sess338 decision), xlog_is_mxfs_foreign_replay(log) discriminator, the
6-family queue-site audit is complete (owner-change was the key omission and
is covered).

## The 5 items and what landed (0.12.6 sv FE2B7E1CF2A875536F20577)
1. **Completion-side shutdown**: xfs_buf_item_done (pal/linux/xfs_buf_item.c
   ~2403) passed shutdown_type SHUTDOWN_CORRUPT_INCORE for foreign buffers
   lacking _XBF_LOGRECOVERY (the bmbt owner-change family) — a live bli
   attached to a victim buffer would suicide the survivor via the not-in-AIL
   delete. Fixed: `(_XBF_LOGRECOVERY || b_mxfs_foreign_recovery) ? 0 : ...`.
   Ordering safe: __xfs_buf_ioend clears provenance AFTER item_done.
   b_iodone audit: xfs_buf_inode_iodone / xfs_buf_dquot_iodone /
   mxfs_dlm_ag_meta_iodone contain NO force_shutdown calls.
2-4. **Ownership-safe provenance**: blind `bp->b_mxfs_foreign_recovery = x`
   before xfs_buf_delwri_queue was unsafe when the queue declines
   (already-queued by live owner → misclassify a live write failure, or leak
   the tag with no completion). New xfs_buf_delwri_queue_recovery(bp, list,
   foreign): assign only on acquisition; equal-provenance requeue (common
   multi-item case) ok; foreign vs live-owner conflict → P227-FR-QCONFLICT +
   -EBUSY → refuses replay (TORN verdict, matches containment design);
   stale foreign tag found by own-log recovery → P227-FR-QSTALE + clear
   (adopted recovery must keep its deliberate shutdown semantics).
   Converted all 6 sites; -EBUSY propagates through each commit_pass2 /
   xfs_btree_visit_blocks. Dquot site now returns the queue error while
   preserving upstream's return-0-on-corrupt-dquot. bwrite arm needs no
   helper (sync, self-owned write, snapshot-consumed provenance).
5. **delwri_fail fail-safe**: untagged buffer would take handle_error's
   _XBF_LOGRECOVERY one-strike shutdown = the exact suicide. Now ASSERT +
   P227-FR-UNTAGGED warn + force-tag before the inline ioend (no-shutdown is
   intrinsic to the op's contract).
   Plus leak-closing: xfs_buf_delwri_cancel and xfs_bwrite tail clear
   provenance (no-I/O abandonment paths).

## State
Built clean (make clean && make modules, 0 errors, only pre-existing
xfs_platform.h warnings). NOT deployed / NOT rig-verified. Fleet on 0.12.4
with durable FSWIDE quarantine on LUN — re-prep (./run.sh 32 caw
prep_cluster) mandatory before the shape-4 run:
TORN_ITEMS=3 VICTIM_LOAD=20 VICTIM_LOAD_MODE=inode
tests/d513_refusal_containment.sh 32 test6 4 → expect TORN/FSWIDE published,
31/31 import, ZERO shutdowns including replayer test1.

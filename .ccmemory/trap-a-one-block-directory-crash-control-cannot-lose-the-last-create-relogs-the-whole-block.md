---
name: trap-a-one-block-directory-crash-control-cannot-lose-the-last-create-relogs-the-whole-block
description: TRAP (sess494): the D-0492 crash control (s493c, buggy build) passed with missing=0 because a ONE-BLOCK shared dir is re-logged by every create; the…
metadata:
  type: feedback
---

# TRAP: a crash-durability control that cannot fail (sess493/494)

The sess493 crash harness (SHAPE=single: 6 rounds x 10 fsync'd creates by two nodes into one shared directory) reported missing=0 on BOTH the buggy 0.70.9 and the fixed 0.70.11 — a non-discriminating pair that would have "verified" the fix vacuously.

Why: a directory of ~120 short names is ONE data block. The retire arm dropped each create's log item at the NEXT create's evict, but that next create re-logged the same block, and the LAST create's surviving item made the AIL push write the whole block (every entry) to the platter. Nothing was ever at risk.

The shape that loses (SHAPE=multiblock, now the default of tests/sess493_d0492_crash_durability.sh): prefill 220 24-char names (3 data blocks, leaf format; xfs_dir2_leaf_addname places a new entry in the LOWEST data block whose bestfree fits), then alternate: unlink a prefill name from block 0 (40-byte hole, non-adjacent), fsync'd 24-char create into that hole (-> block 0), fsync'd 100-char create (fits no hole -> block 2). The second create's modify-refresh evict runs with block 0 committed-unwritten and nothing re-logs block 0 afterwards. Result: 0.70.9 lost 5/5 creates AND undid 5/5 unlinks on both survivors; 0.70.11 lost none with the kept-item path exercised 30x.

Rules: (1) before trusting a crash/durability control, state WHICH block's last modification is unprotected and show the census line proving the arm fired on it after that modification; (2) a shape where every retired block is re-logged before the crash measures nothing; (3) print the at-risk population by name (missing AND reappeared) — an undone unlink is a loss too.

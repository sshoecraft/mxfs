---
name: sess65-CORRECTION-epoch-adopt-only-partial-convergence
description: sess65 CORRECTION: dir_epoch_adopt=1 ALONE gives only PARTIAL extent-map convergence (some ext0 still =2093296 alongside 120); the cleaner all-=120 c…
metadata:
  type: project
---

## sess65 CORRECTION to the two-stage handoff

Final clean run (build FEF626A4, `MXFS_EXTRA_MODARGS='dir_epoch_adopt=1'` ALONE, no merge, no force_block):
- shutdown=0 (clean, no corruption).
- Extent-map convergence is **PARTIAL, not complete**: test1 ext0(131)=daddr120 only, but test2/test3/test4 show BOTH ext0_daddr=120 AND ext0_daddr=2093296. So dir_epoch_adopt=1 alone does NOT fully cure the Stage-1 split — some peers still publish a divergent block0 (2093296) in some rounds.
- The earlier run that showed ALL 4 nodes ext0=daddr120 also had dir_merge=1 active — so the clean convergence claim in [[sess65-HANDOFF-two-stage-node1f1-extent-split-then-content-clobber]] conflated epoch_adopt+merge. epoch_adopt ALONE = partial.
- node1_f1 still lost every round; P64-N1F1 tracer output rolled out of dmesg (firehose) so durability of node1_f1 in block0=120 was NOT captured this run — next session should reduce probe noise or snapshot dmesg per-round (the test already saves /root/drc_create_r${N}_rank${R}.dmesg and drc_fail_*) to capture P64-N1F1 present-flag on daddr=120.

### Revised next-step priority
The split (Stage 1) and content clobber (Stage 2) may share a root: imperfect epoch coverage. dir_epoch_adopt fires on post_release reload, but a node CACHING EX through its whole dd loop never re-acquires, so it never adopts mid-tenure and can still publish a divergent/stale block0. The fix likely needs a WRITE-SIDE guard (dir-inode iflush fence: do not publish extent[0]/block0 content that diverges from the durable disk image for the same incarnation) rather than (or in addition to) the read/acquire-side adopt. GPT-5.5 ranked an iflush FENCE (not merge) as the corruption-prevention guard — combine: acquire-side epoch adopt (converge) + iflush-side fence (don't republish stale). See [[sess65-HANDOFF-two-stage-node1f1-extent-split-then-content-clobber]].</body>

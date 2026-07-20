---
name: sess13run-FINAL-residual-is-concurrent-sameblock-rmw-cohmod-skips-own-undestaged
description: sess13(ccloop) FINAL: dir_coherent_modify=1 (GPT #D, already built) STILL 399/400 with COHMOD-INVAL=0 — never fires because loser's target block is i…
metadata:
  type: project
---

## sess13 (ccloop) FINAL diagnostic — the residual 1/400 is a concurrent SAME-BLOCK RMW conflict

### Tested GPT-5.5's #D (validate data block before placement) — ALREADY IMPLEMENTED as `dir_coherent_modify`
`mxfs_dir_refresh_stale_data_blocks` (xfs_mxfs_dlm.c:1311, gated `dir_coherent_modify`, called from `mxfs_dlm_dir_modify_refresh` ← xfs_create xfs_inode.c:1499 / remove 3845 / rename 4295-97): plain-bdev-reads each cached dir DATA block, fingerprints, and if disk count STRICTLY > cached count, invalidates (clear XBF_DONE) so addname re-reads coherent.

RESULT: winning config + `dir_coherent_modify=1` = STILL 399/400, and **P11-COHMOD-INVAL fired 0 times** across 20 contended rounds × 4 nodes. So it NEVER found a count-behind cached block.

### WHY COHMOD never fires → the true residual mechanism
The refresh SKIPS any block that is `mxfs_dir_buf_is_undestaged || _XBF_DELWRI_Q || !XBF_DONE` (line 1370 — "KEEP our own committed-unwritten work"). In the heavy create wave the LOSER's target data block is THIS node's OWN recent in-flight (undestaged) add → skipped (correctly, else lose own work). But that SAME block is also missing a PEER's durable add at a different offset. So the loser's bestfree (from its own in-flight image) sees offset X free, peer durably used X → collision → 1 dirent lost. Also the refresh deliberately does NOT act on EQUAL-count divergence (same count, different content) — "could be legit reorder".

### CONCLUSION: the residual is a CONCURRENT SAME-BLOCK RMW where two nodes' tenures overlap such that node B's in-core base has B's own uncommitted add AND is missing peer A's committed add to the same block. Proper EX-serialize-then-adopt would give B a base including A's add; B's base missing it ⇒ either (a) B fast-pathed (no adopt — but MHT=0 which forces more adopts made it WORSE 318/400, weakening this) or (b) RELEASE-DURABILITY HOLE: A's add to that block was not durable on the LUN when B acquired+adopted, so the disk B adopted was NOT a strict superset. Leading hypothesis = (b).

### Neither pure-adopt nor pure-keep fixes it — needs ONE of:
1. Close the release-durability hole so disk is ALWAYS a strict superset before any EX handoff (Invariant #1 at the per-DATA-block level under the 2nd-wave burst). INSTRUMENT the bast_process release drain (xfs_mxfs_dlm.c ~6164 loop) to log per-dir-DATA-block dirty/pin/undestaged at unlock for the storm dir — find the ONE block released not-yet-durable. THIS IS THE NEXT RULE-4 STEP.
2. A bounded MERGE of two concurrent same-block adds (GPT cautions fragile, but the divergence is exactly 1 entry — a targeted "re-apply my pending dirent onto the adopted disk block" may be tractable).
3. Stricter serialization so two nodes never have overlapping uncommitted mods to the same dir data block.

### Params that DON'T fix it (all tested with winning config this session): inode_mht_ms=0 (WORSE 318), dir_coherent_modify=1 (no change, COHMOD-INVAL=0). Params that DO (the winning combo): fua_disable=0 fua_always=1 dir_epoch_adopt=1 dir_epoch_convert_gate=1 → 399/400 + 0 shutdowns.
See [[sess13run-HANDOFF-residual-is-data-block-RMW-release-durability-or-concurrency]] [[sess13run-WINNING-CONFIG-fua-plus-epoch-adopt-399of400]].</body>
</invoke>

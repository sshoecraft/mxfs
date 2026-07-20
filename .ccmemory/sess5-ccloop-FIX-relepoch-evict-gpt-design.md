---
name: sess5-ccloop-FIX-relepoch-evict-gpt-design
description: sess5(run6614) FIX build AAA382D5 (GPT-5.5 design, TESTING): gate dir stale-base evict on RELIABLE LOCAL i_dlm_epoch/b_mxfs_relepoch instead of the b…
metadata:
  type: project
---

## sess5 (run 6614) — relepoch-based stale-base evict (GPT-5.5 consult design)

Build **AAA382D5** (TESTING). Addresses [[sess5-ccloop-ROOT-dirreuse-master-epoch-zero-disables-gates]].

### GPT-5.5 consult verdict (RULE-5, proven diagnosis + 5 refuted fixes):
The master dir_epoch propagation is genuinely broken (local granted-lock mirror's stored dir_epoch lags/zeros vs the master's correctly-sent value), AND — more importantly — **dir stale-base correctness should NOT be gated on the master dir_epoch at all**. Use the RELIABLE LOCAL tenure signal: a cached dir buffer is a stale RMW base iff `b_mxfs_relepoch < ip->i_dlm_epoch` (we released/lost the dir grant since this block was last read coherently; Inv-1 drained our work at that release). This is immune to the DLM propagation bug and is the same signal the sess50 write-side reflush-skip already trusts. i_dlm_epoch bumps on grant-loss/release (8 sites, incl. xfs_mxfs_dlm.c:9454).

### FIX APPLIED (mxfs_dir_evict_data_blocks, xfs_mxfs_dlm.c ~4646):
Added `relepoch_stale = (dbp->b_mxfs_relepoch != 0 && dbp->b_mxfs_relepoch < ip->i_dlm_epoch)`. When relepoch_stale && clean (!dirty/!pin/!delwri/DONE) → force `undurable = false` (evict → next read cold-reads peer's image). Also added `!relepoch_stale` to the in-AIL undestaged keep clause. Probe P5-RELEPOCH-EVICT (gated dirwr/instr). Kept the query-max epoch change (dlm.c:2509, harmless).

### GPT's full plan (if evict-only insufficient — next steps): (1) fix DLM: make dir_epoch canonical per-resource, refresh ALL local mirrors + cached-grant re-adopt paths (not first-match-break); query returns res->dir_epoch not a scanned mirror. (2) Enforce relepoch-stale check at the dir buffer READ/return path INCLUDING txn-held buffers (xfs_trans_read_buf), not just evict. (3) Last-chance guard in xfs_dir2_node_addname before the free-slot search: if any placement-influencing buffer (data/leaf/free) is relepoch-stale, force coherent re-read / restart addname. (4) init i_dlm_epoch to 1 not 0; ensure it bumps on VOLUNTARY release too. Acquire-purge is a perf optimization, NOT the correctness backstop.

### CAUTION on regression: a broad read-time salvage that KEPT undestaged buffers REGRESSED dir_reuse this session (over-fired on shared readers). The relepoch-evict is the OPPOSITE direction (force re-read of stale), which is correct. But watch for false-evict of continuous-EX-hold current blocks (relepoch stays current under continuous EX, so should be safe).
See [[sess5-ccloop-ROOT-dirreuse-master-epoch-zero-disables-gates]] [[sess5-ccloop-HANDOFF-state-fixes-and-next]]

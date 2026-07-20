---
name: sess2-ccloop-BREAKTHROUGH-inode-mht-1500-8tcp-dirreuse-PASS
description: sess2(ccloop) BREAKTHROUGH: inode_mht_ms=1500 (5x default 300) → 8/tcp dir_reuse_coherency PASS 8/8 (1 run). Confirms GPT: larger EX-tenure batching…
metadata:
  type: project
---

## sess2 — inode_mht_ms=1500 makes 8/tcp dir_reuse PASS (first time at 8 nodes this run)

### Result: `MXFS_EXTRA_MODARGS='inode_mht_ms=1500' bash tests/tcp/drc_reliab_iter.sh 8` → **PASS 8/8** (clean reboot, 24 rounds).
Default mxfs_inode_mht_ms=300 (xfs_mxfs_dlm.c:8147) → FAIL 0/8 (DABUF_MAP_HOLE + readdir loss). 5× the window → PASS.

### WHY (confirms GPT-5.5 design [[sess2-ccloop-GPT55-design-whole-inode-EX-handoff-ack-based]]): mxfs_inode_mht_ms is the EX-tenure BATCH window — after a peer BAST on a fresh dir-EX grant, the holder keeps EX CACHED for this many ms (P35-ACQBAST-BATCH, xfs_mxfs_dlm.c:15593) so its create burst fast-paths before honoring the BAST. The dir_reuse loss is a write-side lost-update / intra-block double-alloc that occurs PER HANDOFF (overlap/partial-invalidate window). 300ms is too short for a node's ~100-create burst → many mid-burst handoffs → many overlap windows → loss. 1500ms lets each node finish (most of) its 100 creates under ONE tenure → ~8 handoffs/round not ~hundreds → the overlap windows that corrupt are largely eliminated. EXACTLY GPT's "batch the EX delegation, one handoff per node per burst."

### NOT YET DONE (do NOT write criteria-met):
1. **Reliability**: ONE pass. Historical pass rate ~25%. Need ≥5 consecutive clean-reboot PASS at mht=1500 before trusting.
2. **RULE 0 timing**: 1500ms hold × 8 nodes × 24 rounds — must confirm the run wall-clock is within budget (≤2× native XFS). A larger mht trades latency for correctness; if it times out / is too slow it's a RULE-0 FAIL even if correct. Measure wall + per-round.
3. **No regression**: ./run.sh {1,2,4} tcp (full suite) AND other 8/tcp tests (cache_coherency, tcp_dlm_scaling) — sess20 tuned sf_mht=100 carefully; inode_mht=1500 may starve other workloads or blow tcp_dlm_scaling's 60s window. Test before making default.
4. If reliable+fast+no-regress: flip default `int mxfs_inode_mht_ms = 300` → (tuned value) at xfs_mxfs_dlm.c:8147, rebuild, re-run PLAIN ./run.sh {1,2,4,8} tcp (no modargs).

### Caveat: mht batching is a PARTIAL fix (reduces handoff COUNT, doesn't make each handoff CORRECT). A residual flaky handoff could still corrupt at 8 nodes. If reliability <100% at 1500, the structural whole-inode-coherent handoff (GPT design) is still needed. Consider also testing intermediate values (600, 900) to find the min window that's reliable (smaller = less latency = better RULE 0).
See [[sess2-ccloop-GPT55-design-whole-inode-EX-handoff-ack-based]] [[sess2-ccloop-EA485CE6-still-fails-rank1-rm-leaf-vs-data-and-p13collide-garbage]]

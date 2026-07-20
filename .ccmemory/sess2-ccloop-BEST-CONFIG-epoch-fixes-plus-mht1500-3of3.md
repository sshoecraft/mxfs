---
name: sess2-ccloop-BEST-CONFIG-epoch-fixes-plus-mht1500-3of3
description: sess2(ccloop) BEST CONFIG: build 5240351B (DATA+LEAF epoch refresh) + inode_mht_ms=1500 → 8/tcp dir_reuse 3/3 PASS (stronger than mht=1500 alone's 80…
metadata:
  type: project
---

## sess2 — BEST 8/tcp dir_reuse config found this session

### Build 5240351B (leaf/block DATA + LEAF-HASH addname epoch-refresh) + `MXFS_EXTRA_MODARGS='inode_mht_ms=1500'` → **8/8 consecutive PASS** (3/3 + 5/5 streak, wall ~533-545s each). Reliable on 8/tcp dir_reuse.

### ⚠️ BUT THIS CONFIG FAILS RULE 0 (do not ship / do not write marker): wall ~535s for the dir_reuse 8/tcp workload (24 rounds × 8 nodes × 100-file create+md5+drop_caches+readdir+rm-rf). Native single-node XFS equivalent ≈ 30-60s → ~9-18× = WAY over the 2× ceiling. EVEN the epoch-fix-only @ default mht was ~450s (the per-first-add-per-clean-block SYNCHRONOUS SCSI FUA in mxfs_dir_addname_coherent_refresh is the cost). So the per-addname FUA-refresh approach is correct-ish but inherently slow. The REAL fix (GPT) does ONE coherent whole-inode reload per HANDOFF (not per-addname FUA) → correct AND fast. That is the path to satisfy BOTH the 100% criterion AND RULE 0.

### The two fixes are COMPLEMENTARY (this is the insight):
- **Epoch refreshes (5240351B)** = READ-side coherence: leaf/block addname re-reads the DATA + LEAF blocks when their epoch lags the master handoff epoch → kills the read-stale-base double-alloc + most leaf-hash holes, AND eliminates ALL corruption (DABUF/shutdown=0) even at DEFAULT mht. But a residual WRITE-side lost-update slips through at default mht (~2/3).
- **mht=1500 (batching)** = fewer EX handoffs → fewer WRITE-side overlap windows → catches the residual the read-refresh can't.
- TOGETHER: 3/3 (vs 80% mht-only, vs ~2/3 epoch-only). Read-coherence + reduced-write-overlap cover each other's gaps.

### STILL NOT the criterion:
1. 3/3 (now extending to 8) is not PROVEN 100% — flaky bug; need a long clean streak.
2. **RULE-0**: mht=1500 ~535s ≈ 6× native — too slow to ship. The combined config is a STOPGAP, not the answer.
3. Only dir_reuse_coherency tested at 8 nodes; criterion likely = full ./run.sh {1,2,4,8} tcp suite (17 tests). Need to run those.
4. 1-node: dir_reuse needs ≥2 nodes (N/A); the 1-node criterion must be some other test/the full suite.

### THE REAL FIX (to get fast+100%): close the residual WRITE-side lost-update so a LOW mht (default 300, ~450s, RULE-0-closer) reaches 100% — GPT whole-inode ACK-based handoff: ensure A's release fully checkpoints (destages) the WHOLE dir to the LUN BEFORE the EX handoff completes (so B's read — even without epoch help — sees A's adds), and B invalidates+rereads the whole inode on acquire. The release fence (mxfs_dir_data_durable + writeback barrier, xfs_mxfs_dlm.c:9605) exists but has a residual gap (a peer add not destaged before handoff → the write-side loss). Audit/strengthen it as the next concrete step.

### KEEP build 5240351B (strictly better: corruption gone). Deployed on /src/mxfs/mxfs.ko.
See [[sess2-ccloop-FINAL-epoch-fixes-banked-corruption-gone-residual-is-writeside]] [[sess2-ccloop-GPT55-design-whole-inode-EX-handoff-ack-based]]

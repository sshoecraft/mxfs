---
name: sess21-dir_reuse-lowmht-race-negatives-and-precise-localization
description: sess21(ccloop) dir_reuse off-by-one at low shortform-mht: PRECISE localization + NEGATIVE results (not double-grant, not offset-fix, prior-tenure-evi…
metadata:
  type: project
---

## sess21 (ccloop) — dir_reuse off-by-one (readdir=799) at low shortform mht: precise localization + dead ends

Build 7B66691E. The dir_reuse 8-node durable single-entry lost-update is a **fast-handoff TIMING RACE** in the low-`dir_sf_mht_ms` shortform/conversion window. ONLY `dir_sf_mht_ms=300` (high) fixes it (8/8); =100 (default) and =150 fail; but high mht breaks tcp_dlm_scaling speed (see [[sess21-CRITICAL-mht-tradeoff-NOT-resolved-format-gate-broke-dir_reuse-correctness]]).

### CONFIRMED NEGATIVES this session (do NOT re-try):
- **NOT a double-grant**: prior sessions PROVED ex_pop=1 (sole EX holder); the loss is a stale-base RMW by the SOLE holder, not concurrent EX.
- **NOT my merge offset-fix**: offset-fixed merge (7B66691E) + dir_sf_mht=300 = dir_reuse 8/8 PASS, no corruption, no 799. The 799 at low mht is independent of the offset fix (which only removed the dir3_data corruption). [The offset fix is still load-bearing — keep it.]
- **`dir_evict_prior_tenure=1`**: still FAIL (497s, slower). Prior-tenure cached-block eviction does NOT fix it.
- **The reload read IS coherent**: `mxfs_dir_rebase_shortform` reads via `mxfs_pal_bdev_read_plain_bdev` = direct `submit_bio` REQ_OP_READ to the bdev (pal/linux/kern.c:648) → bypasses the initiator's bdev page cache → reads clyde's shared LIO fileio target cache, which HAS the releasing node's durable write (sess84 deterministic dinode flush + blkdev_issue_flush runs for ALL dirs on release, NOT early-outed — xfs_mxfs_dlm.c:7435 early-out is REG-only). So release-durability AND reload-coherency are both correct in code.
- **dirwr=1 logging HIDES the race** (minimal 4tcp repro PASSES with dirwr=1) → cannot use printk instrumentation; need non-perturbing atomic counters.

### THE PARADOX: release-side durability + reload-side coherency both look CORRECT in code, the merge (union) should preserve both peers' entries, ex_pop=1 — yet the entry is durably lost at low mht only. The extra hold-time at high mht masks it. The race is something background-timing-dependent that more hold-time settles (candidates: dir DATA block0 writeback at shortform→block CONVERSION not durable before release at fast handoff — sess68 EVDECIDE=0 means mxfs_dir_evict_data_blocks never iterates for this dir; OR an in-core merge/conversion ordering window). sess61: loss is "dirty bufgen=0 block0 materialized on a stale base" (BLOCK-format data block, post-conversion). sess42: "double sf→block conversion lineage".

### PATHS for next iteration (in priority):
1. **NON-PERTURBING instrument** the shortform→block conversion + block0 durability at release: atomic counters (NO printk) in mxfs_dir_rebase_shortform (fired/adopted/merged/bailed-why) and at the conversion + the release data-block flush; dump once at unmount. Run FULL-SPEED minimal repro (`DRC_NFILES=3 DRC_ROUNDS=12 ./run.sh 4 tcp dir_reuse_coherency`, NO dirwr). Find which path is skipped/stale during a loss round.
2. **Alternatively make tcp_dlm_scaling fast at HIGH mht** so dir_sf_mht=300 satisfies both (high mht fixes dir_reuse): tcp_dlm_scaling at dir_sf_mht=300 fails "within window" (pure speed, RENAME-MISS=0). Investigate why its tiny-churn-dir handoff is slow at high mht and whether the per-tenure cost can drop without lowering the hold that dir_reuse needs.
3. Size-of-dir or grown-flag discriminator for mht (hard: loss is in the small-dir window).

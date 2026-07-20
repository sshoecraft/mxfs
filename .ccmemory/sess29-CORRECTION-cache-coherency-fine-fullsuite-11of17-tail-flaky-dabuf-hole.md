---
name: sess29-CORRECTION-cache-coherency-fine-fullsuite-11of17-tail-flaky-dabuf-hole
description: sess29(ccloop) CORRECTION: cache_coherency is FINE (earlier "0/8" was STALE-LOG reads of full8b's flush_lockwait failure). Clean full 8/tcp = 11/17;…
metadata:
  type: project
---

## sess29 CORRECTION — accurate full-suite picture (supersedes my "environmental cache_coherency" claim)

### METHODOLOGY BUG I made (cost ~1hr): full8.sh writes run.sh stdout to a FIXED path `tests/tcp/drc_cap/full8_run.log`. During a new run's ~2min reset+prep window, that file still holds the PREVIOUS run's content. I polled it and read STALE results — concluding "cache_coherency 0/8 reproduced 4×" when it was ONE genuine failure (full8b, the harmful flush_lockwait=5000 run) re-read 3×. **ALWAYS verify `grep run_id= full8_run.log` matches the current run's launch time before trusting full-suite poll results.**

### CORRECTED: cache_coherency is FINE with the winning config
- 2-test seq (precond_readiness + cache_coherency) = PASS 8/8.
- Clean full suite full8f: cache_coherency PASS 8/8. My levers do NOT break it.

### Clean full `./run.sh 8 tcp` (winning config `dir_gen_per_handoff=1 dir_modify_extent_adopt=1 dir_release_invalidate=1 dir_relinval_clean=1`, build 23FE6715) = **11 PASS / 6 FAIL**
PASS (8/8): precond_readiness, cache_coherency, strong_consistency, posix_multi, mmap_coherency, dlm_fairness, dlm_membership, scaling_curve, dlm_scaling, rsync_paired, **crash_consistency** (passed THIS run — it's FLAKY; hung in an earlier run).
FAIL: **zero_silent_loss** (0/8, ISOLATED — tests after it passed, so no cascade), **dir_reuse_coherency** (0/8) → cascade to fence_during_write, fault_netpartition, soak, tcp_dlm_scaling (all 0/8).

### dir_reuse IN-SUITE failure ≠ standalone failure
- Standalone (drc_passrate2): ~85%, residual = single-dirent 799 loss (relinval_clean mostly fixes it).
- IN-SUITE (full8f): **0/8 = DABUF_MAP_HOLE_OK SHUTDOWN** (xfs_da_btree.c:2876 → Metadata I/O Error → Shutting down). This is the EXTENT-MAP / stale-LEAF staleness (sess20/54 family: a leaf walk maps dir bno=1..4 → a peer-freed block = hole), NOT the dirent loss. release_invalidate+relinval_clean fix the dirent loss + leaf CONTENT but NOT the extent-MAP staleness, which recurs under accumulated in-suite state → shutdown → cascade.

### THE REMAINING 8/tcp BLOCKERS (all in the flaky TAIL; ~11/17 stable)
1. **dir_reuse in-suite DABUF_MAP_HOLE shutdown** = extent-map staleness on EX reacquire (cached i_df extent map references peer-freed dir blocks). Fix dir: on EX reacquire after a peer modified, REBUILD the extent map (mxfs_dlm_reload_inode / dir_ex_stale_refresh exists — find why it doesn't prevent the hole) so the leaf walk never maps to a freed block. sess20 lever dir_postread_reread=1 fixed the hole but TEARS (shutdown) — do not use.
2. **crash_consistency in-suite hang** (FLAKY; ABBA in mxfs_dir_flush_data_blocks blocking xfs_buf_incore at xfs_mxfs_dlm.c:1612). dir_flush_lockwait BAIL was harmful (breaks Inv1). Fix structurally (don't hold i_lock across the buffer get).
3. **zero_silent_loss 0/8** (isolated) — new, uninvestigated. Check if DABUF_HOLE/shutdown too or a real silent-loss.

### NET PROGRESS (real): dir_reuse DIRENT-loss SOLVED standalone (~85%, was ~0%); cache_coherency/crash_consistency confirmed fine standalone; full suite 11/17 (was the keeper's blocker = dir_reuse). Remaining = the deep extent-map/leaf staleness (DABUF_HOLE) + crash_consistency ABBA + zero_silent_loss, all in the flaky tail. Build 23FE6715 (levers default 0 = keeper-safe). See [[sess29-HEAD-handoff-dir_reuse-solved-standalone-fullsuite-env-blocked]] (note: that memory's "environmental cache_coherency" claim is WRONG — corrected here) [[sess20-PROVEN-dabuf-hole-is-stale-leaf-fixed-by-postread-leaf-only]] [[sess29-BREAKTHROUGH-dir_reuse-8tcp-4of4-relinval-clean]].

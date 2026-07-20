---
name: sess12run-RESULT-vector1-2-fixes-sound-but-inert-vector3-dominant
description: sess12(ccloop) RESULT: ABA write-guard + shortform-rebase fixes (build 40AC2A0C) are SOUND/no-regression but fire 0x and DON'T fix dir_reuse — domina…
metadata:
  type: project
---

## sess12 (ccloop) RESULT — vector-1/2 fixes sound but insufficient; vector 3 is the dominant blocker

### Build 40AC2A0C (KEEP, default-on params, NO regression): two fixes
- `dir_ex_write_guard=1` (pal/linux/xfs_buf.c): skip a disk-proven clobbering dir DATA/LEAF write when NOT holding dir EX. [[sess12run-THREE-VECTORS-stale-base-RMW-and-ABA-writeback-fix]]
- `dir_sf_rebase=1` (xfs/xfs_mxfs_dlm.c mxfs_dir_rebase_shortform, called from modify_refresh): wholesale rebase a stale in-core SHORTFORM i_df from the durable disk dinode on a tenure-advanced modify (uncached plain-read, gated gen!=0 && gen!=evicted_gen + memcmp guard). [[sess12run-GPT-DESIGN-tenure-rebase-dir-coherency-unified]]

### EMPIRICAL RESULT (drc4_capture/drc4_repro, dirwr=2)
- Run 1: 24 rounds CLEAN (first clean run all session!) — but P12-SF-REBASE=0 AND P12-DIR-EXGUARD-SKIP=0 → NEITHER fix fired. The clean pass was STOCHASTIC luck.
- Run 2: FAIL round 10, single entry node1_f15.md5 lost (LOOKUP_ENOENT all nodes). Both probes still 0×.
- Full 4/tcp suite on the prior build (B5FB078A, vector-1 only): 12 PASS (no regression of core passers), dir_reuse 0/4, fence_during_write shutdown + cascade unchanged.

### INTERPRETATION
The DOMINANT failure mode is SINGLE-DIRENT loss (node1_f15.md5, node4_f1, node1_f42.md5 in various runs) = VECTOR 3 (intra-create revert, sess11 DECISIVE): a create commits a dirent (addname rval=0) that is ABSENT from in-core ~30us later at durable_signal, SAME thread, ILOCK_EXCL held, dir gen bumped 4→5 DURING the create. Neither my fix touches this. ALSO: the ABA leaf clobbers (vector 1, e.g. the earlier 127-vs-402) apparently happen while the writer DOES hold EX (dir_held_ex), which my guard intentionally does NOT skip — so EXGUARD never fired. So vector 1 may also be an under-EX revert, not purely a not-EX background flush.

### NEXT SESSION (priority order)
1. VECTOR 3 (dominant): instrument the create to timestamp (a) dir EX acquire/upgrade + the i_dlm_dir_gen bump (find the ++ site that fires mid-create: candidates xfs_mxfs_dlm.c:11364, 14367, xfs_dir2_readdir.c:698) vs (b) addname entry placement vs (c) durable_signal. PROVE whether a reload/evict runs BETWEEN addname and durable_signal. Then apply GPT's design: the PR→EX upgrade + rebase MUST complete BEFORE addname; a BAST/gen-bump during an active create MUST be DEFERRED (revoke_pending), never reload mid-txn. Implement the per-dir begin_modify/end_modify state machine (GPT design in [[sess12run-GPT-DESIGN-tenure-rebase-dir-coherency-unified]]).
2. Reconsider whether vector 1's clobber is under-EX (if so, the EX-guard needs a tenure-stale check even under EX, but CAREFULLY — that's the refuted dataclobber>=2 territory; the safe version is GPT's "old-tenure buffers must not remain dirty/writeable after EX release" — INVALIDATE on release, not skip on write).
3. Separately: fence_during_write corruption-0x8 (xfs_defer) — different AG/extent root.

### KEEP the two fixes (sound, no regression, target real vectors seen in other runs); they are necessary-but-insufficient parts of the unified tenure-rebase architecture.
Criterion NOT met. Cluster left mounted (build 40AC2A0C). See [[sess12run-CLEAN-BUILD-4tcp-baseline-two-real-bugs]].
</body>

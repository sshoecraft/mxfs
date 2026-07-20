---
name: sess19run-UNTESTED-handoff-gated-coherent-modify-build-F141D09D
description: sess19(ccloop) UNTESTED build F141D09D: made dir_coherent_modify HANDOFF-GATED (new i_dlm_dir_coherent_gen) to fix its 5× slowness. TEST FIRST: mht=5…
metadata:
  type: project
---

## sess19 (ccloop) — UNTESTED change at the relay boundary: handoff-gated coherent-modify

### Build `F141D09D` (builds clean). The most promising path to the criterion — TEST THIS FIRST next session.

### What changed (2 files):
- `xfs/xfs_inode.h`: added `uint32_t i_dlm_dir_coherent_gen` to struct xfs_inode (after i_dlm_dir_evicted_incarn).
- `xfs/xfs_mxfs_dlm.c` `mxfs_dir_refresh_stale_data_blocks()` (the dir_coherent_modify per-block scan): added a HANDOFF-GATE after the `i_dlm_dir_gen==0` check — `if (ip->i_dlm_dir_gen == ip->i_dlm_dir_coherent_gen) return; ip->i_dlm_dir_coherent_gen = ip->i_dlm_dir_gen;`. So the expensive scan runs ONCE per cross-node handoff (gen advance) instead of on EVERY addname.

### WHY: this session PROVED `mht=50 + dir_release_invalidate=1 + dir_coherent_modify=1` is CORRECT (failrounds=0 through round 6) but ~5× too slow (~60s/round) because dir_coherent_modify re-read every dir block before every addname (O(blocks×creates)). Under EX no peer modifies mid-tenure, so one scan per tenure (handoff) suffices → O(blocks×handoffs). See [[sess19run-dir-coherent-modify-correct-but-too-slow-need-handoff-gated]].

### TEST PLAN (next session, FIRST thing):
1. Deploy F141D09D. Clean reboot. `MXFS_EXTRA_MODARGS='inode_mht_ms=50 dir_release_invalidate=1 dir_coherent_modify=1' TEST_TIMEOUT=400 ./run.sh 8 tcp dir_reuse_coherency`. Check failrounds (want 0) AND wall (want <300s; run portion = rank1 r1-create-start→r24-rm-done).
2. If correct+fast: this resolves dir_reuse @ mht=50. Then set defaults: `inode_mht_ms=50`, `dir_release_invalidate=1`, `dir_coherent_modify=1` in code, re-run FULL `./run.sh 8 tcp` (tcp_dlm_scaling passes @ 50; verify all 17). Then re-validate 1/2/4 tcp full suites (mht=50 changes their behavior — must confirm no regression).
3. RISK if it has a residual: the handoff-gate relies on i_dlm_dir_gen bumping on EVERY cross-node handoff. P63-FASTEX-HANDOFF was 0 (all handoffs slow-path, which DO bump gen) in this workload, so likely OK — but if a residual appears, the gen-bump reliability (FASTEX fast-path) is the gap; the per-addname version caught it by re-checking every time.

### Fallback state: build 15447D0C = last KNOWN-GOOD KEEP (inode-skip fix, all dir params default off, mht 300). F141D09D adds only the (default-off) handoff-gate + the new field — safe to keep as the baseline once tested. The inode-skip fix (cache_coherency etc. all 8/8) is validated. See [[sess19run-FULL-8tcp-suite-13of17-mht-tradeoff-is-core-blocker]], [[sess19run-PROGRESS-dir-release-levers-cut-lowmht-loss-18to4]].
</body>

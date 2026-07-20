---
name: compiled-dirreuse-8tcp-release-levers-lowmht-tradeoff
description: sess19 ccloop: dir_release_invalidate lever cuts low-mht dir_reuse loss 18→2; mht tradeoff blocks 8/tcp suite; reload must stay handoff-gated.
metadata:
  type: project
tags: [compiled, dir_reuse, mht-tradeoff, 8tcp-suite, dir-release-invalidate, handoff-reload, sess19]
---

## sess19 (ccloop) — dir_reuse @ low-mht: the release-invalidate lever, the mht tradeoff, and handoff-gated reload

Central topic: making the `dir_reuse_coherency` criterion CORRECT at low `inode_mht_ms` so a single global mht default can pass the full `8/tcp` suite. The one global `inode_mht_ms` has **opposite needs** across two criteria — this is THE ship blocker for `./run.sh 8 tcp`.

### The core blocker — the mht tradeoff (full-suite characterization)
[[sess19run-FULL-8tcp-suite-13of17-mht-tradeoff-is-core-blocker]]: first full `./run.sh 8 tcp` = **13 PASS / 4 FAIL** (build `0A6350A1`, mht=275 default).
- PASS (13): precond_readiness, cache_coherency, strong_consistency, zero_silent_loss, crash_consistency (all coherency-critical — proves the inode-skip fix is SAFE), posix_multi, mmap_coherency, dlm_fairness, dlm_membership, scaling_curve, dlm_scaling, rsync_paired, soak.
- FAIL (4): `dir_reuse_coherency` 0/8 (no-result, KILLED by 300s TEST_TIMEOUT; passes STANDALONE ~294s, 6s margin too thin — cascade root); `fence_during_write` 7/8 + `fault_netpartition` 7/8 (CONTAMINATION, both PASS 8/8 standalone after clean reboot — cascade from dir_reuse timeout wedging the cluster, test5 cited); `tcp_dlm_scaling` 1/8 (REAL 8-node failure even truly-standalone: test5 `connection1:0: detected conn error (1020)` iSCSI drop + test2 `P36-RETRY ino=0 type=3 mode=EX` acquire timeout, `TDS rank=2 rounds=150 window=60` elapsed=115s = 2× too slow for 60s window).

The tradeoff, confirmed ([[sess19run-dir-loss-at-low-mht-is-reload-selfclobber-not-trylock]]):
- `tcp_dlm_scaling` needs **LOW mht (~50)**: PASS 8/8 @ mht=50 (40s); at mht=275 each node holds DLM locks 275ms → 150-round window blows (115s vs 60s) → acquire-timeout + test5 iSCSI conn-error 1020 cascade.
- `dir_reuse` needs **HIGH mht (≥275)**: PASS @ mht=275 (~294s); @ mht=50 the dir-EX handoff rate is ~10× higher → dir free-slot reload race → durable dirent loss (round7=797/800, round8=670/800 = 130 lost, ALL nodes agree = durable on-disk, lookup_fail=0 = readdir SHORTFALL not lookup miss). 18/24 failrounds.
- **ONLY resolution:** make dir-heavy tests CORRECT at LOW mht, then set default mht=50 → BOTH pass. The inode-skip fix does NOT address dir reload (inode coherency, not dir free-slot). Reproduce: `MXFS_EXTRA_MODARGS='inode_mht_ms=50' TEST_TIMEOUT=300 ./run.sh 8 tcp dir_reuse_coherency` after clean reboot.

### The breakthrough lever — dir_release_invalidate
[[sess19run-PROGRESS-dir-release-levers-cut-lowmht-loss-18to4]]: A/B at mht=50, build `15447D0C`, RULE-4:
- plain mht=50: **18 failrounds** (heavy, up to 130/800 lost), ~233s.
- `dir_release_invalidate=1` ALONE: **2 failrounds** (round10 + round23, each 799/800 = ONE dirent lost), ~305s. **~9× loss cut.**
- `dir_release_invalidate=1 + dir_release_fua_write=1`: **4 failrounds** → `dir_release_fua_write` REFUTED (worse 2→4, and slower; do not use).
- **`dir_release_invalidate=1` (`xfs_mxfs_dlm.c:2524`) is the key lever**: on dir-EX release, invalidate clean+durable dir DATA/leaf buffers so the next acquire cold-FUA-reads the coherent LUN image ("no dir buffer survives a handoff"). Default currently 0; should become DEFAULT 1 once residual + speed solved.

### Refutations — reload must stay handoff-gated, NOT continuous
[[sess19run-REFUTED-force-coherent-worse-reload-must-stay-handoff-gated]]:
- `force_coherent=1` @ mht=50 REFUTED — made it WORSE, **24/24 failrounds** (vs 18/24). force_coherent (`xfs_da_btree.c:3340`) invalidates dir blocks on EVERY read, not just on handoff → discards the node's own COMMITTED-BUT-NOT-YET-DRAINED in-core dir work MID-TENURE (release-drain lands work at RELEASE, not continuously) → self-clobber. Reload MUST stay handoff-gated (invalidate only on cross-node re-acquire).
- `P34-TRYLOCK-STALE` is NOT the main cause — fires only 5-32× per failing mht=50 run while loss is ~130 entries; a bounded-retry would not fix it. (Refutes sess18's TRYLOCK-skip lead.)
- `P116-RELOAD-SELFCLOBBER` / `P103-RELOAD-REUSE-ADOPT` are INODE reload paths (`mxfs_dlm_reload_inode`; di_size/di_mode/gen), NOT the dirent loss. P116 is a `-SKIP` GUARD (high count = inode-reuse churn, red herring).
- The dirent loss lives in the DIR-DATA-BLOCK handoff reload: `P63-HANDOFF`/`P64-MASTER-HANDOFF` (~138-160×), `P62-RELOAD` (280×), `P65-EPOCH` (~138×). Rare at mht=275, heavy at mht=50.

### Refined diagnosis of the residual loss
Two competing sub-hypotheses for the residual single-dirent losses (after `dir_release_invalidate=1`, round10/round23, 799/800, durable, all nodes agree, lookup_fail=0):
1. **Release-side under-drain** ([[sess19run-dir-loss-at-low-mht-is-reload-selfclobber-not-trylock]]): a dir block NOT clean+durable at the release-invalidate moment (in-AIL/pinned) is SKIPPED by the invalidate (correct — can't drop undurable own work) → survives handoff → stale base → 1-dirent clobber. Releasing node hands off dir-EX before its just-added dir-DATA blocks are durably on the LUN; at low mht a release-fast-path may skip/rush the dir-data drain. The release-DRAIN loop (`xfs_mxfs_dlm.c:6592`) should make it durable before the invalidate, but a timing gap remains.
2. **Acquire-side reload miss** ([[sess19run-REFUTED-force-coherent-worse-reload-must-stay-handoff-gated]]): after release, work IS drained durable (disk has everything), so FUA-reading disk on re-acquire is SAFE. Bug = on re-acquire the node sometimes serves its STALE warm prior-tenure cache instead of FUA-re-reading → addname RMWs stale base → durable clobber. The gen-invalidation (`xfs_da_btree.c:3176`, handoff-gated via `i_dlm_dir_gen` bump on P63/P64) is the RIGHT mechanism but misses occasionally. Candidate gaps: (a) `i_dlm_dir_gen` bump doesn't fire on every real cross-node handoff (`P63-FASTEX-HANDOFF`/`P-FASTEX-EPOCH` were 0 in one capture — FASTEX fast-path handoff-detect may under-fire; check `mxfs_v5_dlm_inode_grant_handoff` + dir_epoch_adopt); (b) LEAF-format 800-entry dir addname uses the leaf `bests[]`/freeindex block — verify THAT block is invalidated+FUA-reloaded on handoff, not just data blocks; (c) per-block invalidation stamps `b_mxfs_dir_gen` but addname may select a different block than the one invalidated (via bestfree).

### Concrete next-step to disambiguate release vs acquire
[[sess19run-NEXT-check-dir-data-durable-invoked-at-lowmht-release]]: verify the release-side durability fence is actually INVOKED at every dir-EX release at mht=50 (not skipped by a release-fast-path).
- Fence = `mxfs_dir_data_durable(ip)` (`xfs/xfs_mxfs_dlm.c:988`) + `mxfs_dir_flush_data_blocks` + `mxfs_dir_push_data_ags` (`:1118`) = Invariant-#1 ("no DLM unlock without drain"; dir DATA/leaf blocks landed durable BEFORE dir-EX BAST/unlock). Looks complete for EXTENTS+BTREE (sess98 IN_AIL gate, sess133 BTREE). The dir-EX RELEASE drain (`xfs_mxfs_dlm.c:6592`) runs UNCONDITIONALLY for dir inodes, loops until `!in_ail && !pinned && mxfs_dir_data_durable(ip)` with the sess97 `xfs_bwrite` checkpoint fence — CONFIRMED robust, NOT fast-path-skipped.
- The open question: does a release-fast-path (`relflush_skip`/`dir_pr_release_fast`/`relsettle_skip`/clean-release `log_force` skip) bypass the dir-data drain at HIGH frequency low mht? Those fast-paths are speed wins for mht=275 but may UNDER-DRAIN dir-DATA at mht=50. ACTION: instrument the dir-EX release/BAST path — log whether `mxfs_dir_data_durable` ran AND returned durable vs was skipped, correlate skipped-releases with failing rounds, and re-test with those fast-paths disabled. Also verify `bast_work_fn` Phase-2 drain (drain_meta/alloc/inode + blkdev_flush) covers dir DATA/leaf/free blocks at low mht.

### Speed problem (RULE 0, first-class)
- `dir_release_invalidate=1` @ mht=50 = **305s** (over the 300s budget) — the invalidate forces cold-FUA re-reads every acquire; at mht=50's high handoff rate that's many FUA reads. Standalone dir_reuse ~294s (was ~315 pre-fix). Cost = FUA-read latency (~150k SCSI FUA/node/run, ~0.93ms each).
- DIR-block thrash dominates: same ~17 blocks re-read ~336×/round during rm+verify, with **DIRINVAL=0** (so NOT the gen-invalidation) → blocks reach read NOT-XBF_DONE via EVICTION (mechanism unfound). Cracking it could cut rm 3.5s→0.5s = huge margin. Lead: find the dir-buffer eviction source (`xfs_buf_stale` on live blocks? LRU `b_lru_ref=0`?).

### Build markers / KEEP
- **`15447D0C`** KEEP baseline — inode-cluster cached-allocated skip (`xfs_icache.c` `mxfs_dinode_cached_allocated` + param `inode_cluster_owned_skip=1`): inverse of the sess38 cached-FREE ENOENT bug; skip re-FUA of the 32-inode cluster when cached cluster shows THIS inode ALLOCATED (content still refreshed at ilock). Cut inode FUA ~30% (igstale 5376/8rounds → 0), validated SAFE across ALL coherency tests (cache_coherency/zero_silent_loss/strong_consistency/crash_consistency all 8/8). mht default 300 in this build.
- **`0A6350A1`** — full-suite run build; same inode-skip fix, mht default 300→275 (`xfs_mxfs_dlm.c:5402`). RECONSIDER: 275 helps dir_reuse but breaks tcp_dlm_scaling; the real target is low mht + reload fix, not a compromise default.
- Diagnostic counters (FUA-COUNT scsi/p91skip/oskip/igstale) always-on; probes P19-INOFUA, P15-DIRFUA, P19-DIRINVAL gated behind `dir_perf_probe=1`. P-DIRWR / P98 / sess60 dir-release probes behind `mxfs_instr=1` (~100× slow — use sparingly, 2 rounds).

### Next-session plan (consolidated)
1. Disambiguate release-side under-drain vs acquire-side reload-miss by instrumenting the dir-EX release path (durable-ran vs skipped) AND the acquire-side i_dlm_dir_gen bump firing on every cross-node handoff. Test with release-fast-paths disabled.
2. Close the 2 residual single-dirent losses — either ensure invalidate runs only AFTER every dir block is durable, or invalidate ALL blocks (incl. not-yet-durable) by first force-landing them; verify the leaf bests[]/freeindex block is on the invalidate+reload path.
3. Reduce the mht=50 FUA-read cost to fit 300s (find/kill the dir-buffer eviction thrash source).
4. Set `dir_release_invalidate` default 1 + mht default 50; re-validate full 8/tcp suite.

Marker NOT written (as of sess19 ccloop).

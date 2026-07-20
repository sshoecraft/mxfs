---
name: sess10run-NEXT-real-fix-direction-concurrent-rmw-stale-base
description: sess10(ccloop) NEXT-STEP direction for 4/tcp dir_reuse durable single-dirent loss: it's a concurrent same-block dir RMW stale-base clobber; needs cod…
metadata:
  type: project
---

## sess10 (ccloop 4cb2d0a2) — sharpest direction for the 4/tcp dir_reuse durable loss

### The bug (re-confirmed clean, build DE3A7E21)
`./run.sh 4 tcp dir_reuse_coherency` standalone FAILs ~80%+: a durable single-dirent loss (one create's entry, e.g. node4_f1.md5 / a `.md5` sidecar). ALL nodes readdir=399/400 lookup_fail=0. **Survives the test's `drop_caches` → durable on-disk loss**, not intra-node staleness. 2/tcp PASSES (concurrency-threshold bug). NO FS shutdown/corruption.

### Mechanism (best supported by evidence)
4 nodes concurrently create into ONE shared dir (leaf format, multiple data blocks). Two nodes' dirents hash to the SAME data block. A node RMWs that block from a STALE in-core base (missing a peer's durably-committed entry) and flushes → clobbers it. The dir INODE EX serializes the RMWs; the GAP is dir-DATA-BLOCK cache coherency across the EX handoff. sess61-DECISIVE: the clobber block is DIRTY (bufgen=0), so the read-path invalidation (xfs_da_read_buf, gated b_mxfs_dir_gen<i_dlm_dir_gen) SKIPS it (can't clear XBF_DONE on dirty = would lose own work) → stale-dirty base RMW.

### Why all existing mechanisms are insufficient (don't re-try as the fix)
ALL of these are present/ON and still fail: epoch adopt (dir_epoch_adopt, sess64 — refuted reliable this sess), one-shot grant_handoff (P63-FASTEX-HANDOFF, fires but loss persists), lossy i_dlm_dir_gen evict-ring, dir_modify_extent_adopt=1, dir_postread_reread=1, dir_iflush_owner_fence=1, dir_force_block=1, dir_adopt_block=1. Param combos (dirrefresh, dir_leaf_rebuild) don't help.

### THE decisive unanswered question for next session (RULE 4 step 1)
At the actual CLOBBERING write, is the target data block:
  (A) DIRTY/in-AIL-stale (Invariant-1 drain GAP at the prior release — block not fully destaged, so it's dirty at reacquire and the invalidation skips it), or
  (B) CLEAN-stale (refresh-signal GAP — clean block whose b_mxfs_dir_gen wasn't bumped past i_dlm_dir_gen on this tenure's reacquire)?
Instrument: at the dir-DATA write submit for a CONTENDED dir (P16-DIRBLK-SUBMIT / P35E-DIRWR already exist, dirwr=2), capture for the SPECIFIC block that loses an entry: XBF dirty/in_ail/pin, b_mxfs_dir_gen vs dp->i_dlm_dir_gen, and whether a handoff/epoch fired THIS tenure. Correlate cross-node by daddr+realns to find the write that dropped node4_f1.md5 vs the peer write that added it. (sess69 has dirwr=2 RD/WR-lineage tooling.)

### Fix per branch
- If (A) dirty-stale: the prior release did NOT fully drain that data block (Invariant-1 violation). Suspect the Phase-3 `meta_pending timeout after 2s — forcing release` (xfs_mxfs_dlm.c:16630) and/or dir-data drain (mxfs_dir_flush_data_blocks) skipping a transiently-locked/in-flight block. FIX: guarantee the dir's DATA blocks are CLEAN on the platter at EX release (so a peer's reacquire invalidation can evict+refetch). Do NOT force-release dir inodes on drain timeout.
- If (B) clean-stale: a reacquire path reads the block without bumping/checking dir_gen, or b_mxfs_dir_gen was pre-bumped to current by an earlier same-tenure read. FIX: force a coherent re-read of ALL cached data/leaf blocks of a contended dir at EX modify acquire (clear XBF_DONE on CLEAN blocks unconditionally when dir_gen>0), independent of the per-block gen stamp.

### Separately (also blocks the criterion): in-suite CONTAMINATION
Full `./run.sh N tcp` fails extra tests that PASS standalone (fence_during_write, fault_netpartition, tcp_dlm_scaling at 2/4; crash_consistency flaky at 4). run.sh preps ONCE (mkfs+mount) and runs all 17 tests with NO inter-test cluster recovery; node-disrupting tests (crash_consistency reboots; fence/netpartition) degrade the cluster for later tests. sess58 got clean 2/tcp 17/17 so it WAS achievable — likely a sess59-69 regression or needs run.sh inter-test health-gate+recovery. Criterion = clean full ./run.sh 1/2/4/8 tcp 100%.

### Env: test1-8 VMs all up/reachable. Reset: virsh -c qemu:///system destroy+start. Repro: `./run.sh 4 tcp dir_reuse_coherency` (~5min); trace `MXFS_EXTRA_MODARGS='dirwr=2' MXFS_TEST_ENV='DRC_ROUNDS=20 DRC_STREAM=1'`; lost name in `mxfs-drc-RDMISS round=N`; per-round dmesg snapshots at /root/drc_create_r<N>_rank<R>.dmesg on each node. Bash tool default timeout 120000ms — set higher or run_in_background for run.sh.

See [[sess10run-4tcp-clean-repro-dirty-block-clobber-mechanism]] [[sess69-TRUE-ROOT-crossnode-stale-readcache-hit-poisons-rmw-base]] [[sess61-DECISIVE-dirty-bufgen0-divergent-block0-kept-by-dirty-guard]].</body>

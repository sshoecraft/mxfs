---
name: sess51-dir-reuse-exposed-by-durability-skip-stale-block-race
description: sess51: tcp_dlm_scaling FIXED (durability-skip, 4/4). But it EXPOSED dir_reuse_coherency's sess37 stale-block-RMW race (was masked by the removed ful…
metadata:
  type: project
---

## sess51 — tcp_dlm_scaling FIXED; dir_reuse_coherency now the residual

### tcp_dlm_scaling: FIXED (build FFC0DA1D, `dir_pr_release_fast=1` default, xfs/xfs_mxfs_dlm.c).
Skip `mxfs_dlm_dir_inode_durable` in `mxfs_dlm_bast_process` when the dir is PROVABLY clean
(p_held_mode != EX && xfs_inode_clean && !in_ail && pin==0). Captured held mode at entry (before
~L4744 sets NL). PROVEN: tcp_dlm_scaling PASS 4/4 (full run + reliability 1/2/3); max_drain_ms
2000→1-3; EDEADLK hundreds→1-2; TDS-LEFTOVER=0; 0 shutdowns. P51-REL log (always-on ratelimited,
held_mode/clean_skip/drain_ms) added at the unlock site.

### NEW residual: dir_reuse_coherency intermittent (failed 1/4 with my build; passed 5/5 in
sess49/50 old build). NOT force_block-fixable: sess44 PROVED force_block=1 breaks dlm_fairness +
cache_coherency (P43B keeps stale in-core BLOCK vs peer's legit block→sf → BNOBT double-free →
shutdown). Current source has `mxfs_dir_force_block = 0` (sess44 reverted; comment still says
"sess43 DEFAULT ON" — stale comment).

### HYPOTHESIS (strong): my durability-skip EXPOSED the sess37 stale-block race by removing an
INCIDENTAL masking barrier. Old behavior: log_force(XFS_LOG_SYNC) on EVERY dir release (incl clean
PR) drove xfsaild/delwri writeback to complete → few LOCKED stale dir blocks at the next acquire.
sess37 ROOT (still unfixed): the read hook (xfs_da_btree.c ~3101) AND acquire-evict
(mxfs_dir_drain_evict_data_blocks ~3603) both use XBF_TRYLOCK and SKIP a LOCKED (-EAGAIN) stale
dir block (in-flight self delwri/AIL writeback) → an RMW on that stale base durably drops a peer's
dirents (data-loss: missing node1_f1.. first contiguous; OR leaf-hash: readdir=200 lookup_fail on
node1_f47-50.md5). Read-side CANNOT block (deadlock: holds inode DLM, starves peer grant — comment
~3092). Acquire-side blocking is documented-safe (sess97) but deeply-worked/risky.

### FIX OPTIONS (decide on repro data):
1. Narrow durability-skip to SELF-DEMOTE (EDEADLK recovery, L9370) only — keep masking barrier on
   peer-handoff releases dir_reuse needs. Risk: may not fully fix tcp_dlm_scaling if peer-BAST PR
   releases dominate the livelock cost.
2. Fix the stale-block race at acquire: make the -EAGAIN LOCKED-SKIP in
   mxfs_dir_drain_evict_data_blocks WAIT (bounded) for the buffer writeback then invalidate.
   sess37 said read-side cond_resched retry REFUTED, but acquire-side real wait (msleep, waits for
   I/O) differs. Gate behind module param for A/B.

### Repro harness: tests/tcp/sess51_drc_repro.sh (5 full runs, clean reboot, captures
drc-FAIL/RDMISS/P43/P34D/FMTREVERT dmesg per failing run to /tmp/sess51_drc_run*_*.dmesg).
Criterion (sess43-confirmed) = FULL ./run.sh 2 tcp 17/17 reliably. Cluster build FFC0DA1D.
Related: [[sess51-ROOT-tcp-dlm-scaling-is-symmetric-PR-EX-dir-upgrade-livelock]] [[sess37-drc-real-root-is-stale-block0-leaf-RMW-not-datainit]] [[sess44-BREAKTHROUGH-force-block-1-is-the-regression]]

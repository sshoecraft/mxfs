---
name: sess49-BREAKTHROUGH-epoch-adopt-0-fixes-8node-shutdown
description: sess49(ccloop) BREAKTHROUGH: dir_epoch_adopt=0 FIXES 8/tcp dir_reuse shutdown → PASS 8/8 (0 RDMISS, 0 shutdown). epoch_adopt=1 (sess14-48 regression)…
metadata:
  type: project
---

## sess49 (ccloop 4cb2d0a2) — BREAKTHROUGH: epoch_adopt=1 was the 8-node regression

### MEASURED (drc_dirtyskip.sh, 24 rounds, 8 nodes, fresh reboot each):
- **dir_epoch_adopt=1 (the sess14-48 default): 0/8 FAIL — deterministic FS SHUTDOWN ~round 10** (AG free double-free `ltbno+ltlen>bno` in xfs_free_ag_extent + P21H-LEAFHOLE + dir-fork DELAYSTARTBLOCK(-2)). readdir=0 after shutdown.
- **dir_epoch_adopt=0: PASS 8/8, all 24 rounds, 0 RDMISS/CLASS, 0 shutdown.** Clean.
- 4-node PASSES with EITHER value (the corruption needs heavy 8-node handoff churn).

### ROOT (code-traced): mxfs_dir_epoch_adopt=1 sets genuine_handoff=true in mxfs_dlm_reload_inode when grant_epoch>valid_epoch (xfs_mxfs_dlm.c:11181). genuine_handoff BYPASSES the keep-stale guards P33-DIRGROW-REVERT-SKIP (~11884 `if (dg_inflight && !genuine_handoff)`) and P43-FMTREVERT-SKIP (~11983). So the reload runs xfs_idestroy_fork + xfs_inode_from_disk and ADOPTS a STALE-SMALLER disk dinode (our just-grown dir block not yet destaged) -> SHRINKS the in-core data fork -> a leaf-referenced block becomes a HOLE/DELAYSTARTBLOCK -> dabuf_map !HOLE_OK + AG double-free -> shutdown. The sess63 comment justifying the bypass ("genuine handoff => prior tenure drained at release => disk authoritative even if in-AIL") is FALSE when the release-drain is incomplete for the dir grow.

### THE FIX (build 3B0EB406BB1B244571440B6): baked `int mxfs_dir_epoch_adopt;` = DEFAULT 0 (was =1, xfs_mxfs_dlm.c:5291). Reverts to the conservative reload that KEEPS the authoritative in-core fork when dirty/grant-held — recovers the sess18 (build 58360875) state where 8/tcp dir_reuse PASSED 8/8 at mht=300 (the reload residual masked by mht=300's longer EX hold; speed was the only sess18 blocker). gen_per_handoff stays =1 (only bumps a read-invalidation counter, doesn't rebuild the fork — harmless, kept on through the PASS).

### NEXT (verify 100%): (1) re-run 8/tcp with BAKED default (build 3B0EB406, no modargs) — confirm 8/8. (2) RELIABILITY: ≥3-5 consecutive clean-reboot 8-node runs (handoff noted variance: sess18 reload residual is masked not fixed -> watch for an occasional RDMISS). (3) re-confirm 1/2/4-node still PASS with epoch_adopt=0. (4) consider full `./run.sh 8 tcp` suite. RULE-0: ~16-25s/round is slow (owner_scan per-AG rhashtable walk) — speed is a separate concern but the criterion is correctness 100%.

See [[sess49-8node-shutdown-is-agdoublefree-from-epochadopt-stale-reload]] [[sess49-fix-design-genuine-handoff-must-honor-shrink-skip-when-dirty]].
</body>
</invoke>

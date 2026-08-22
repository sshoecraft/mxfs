---
name: ccloop-c7ee71c6-sess240-23-closed-488-new-aglock-livelock-defect
description: sess240: #23 CLOSED (0.11.488 both race exercises PASS); NEW critical AG-lock livelock: test30 rsync cycles all 25 AGs -EAGAIN forever, peers idle+ho…
metadata:
  type: project
---

# sess240 — #23 closed on 0.11.488; new AG-lock livelock defect found

## #23 D-OPEN-PROTECT-DEMOTE-RACE-SPURIOUS-EIO: FIXED AND VERIFIED (ledger closed, 33 open)
- 0.11.488 sv FF625592172DA86D351A8AF built + swap-deployed 32/caw.
- tests/openprotect_race_ab.sh 60 → PASS: inject_landed_window=60, restarts=60 all try=1, admit_defers=0, protect_fail=0, userspace_fails=0.
- tests/openprotect_race_ab.sh 30 gate → PASS[gate]: P95-OPEN-ADMIT-DEFER ×989, PF=0, ufails=0, arm B completed (eventual demotion proven).
- Ledger fields fix_sess239 / verify_sess240 carry full evidence.
- Deploy trap: module_swap_deploy.sh's 8×5s rmmod retry is too short after heavy runs — 8 nodes needed ~20 retries. Manual longer pass then rerun → SWAP_OK.

## NEW CRITICAL DEFECT (unledgered at session end — next session must ledger)
rsync_paired board cell FAIL (0/32 NO_TERMINAL_RECORD, run 20260811T024231Z, logs /tmp/run_rsync_paired_20260811T024231Z):
- test30's rsync (PID 18371) permanently livelocked in mxfs_ag_dlm_lock_bounded (xfs/xfs_mxfs_dlm.c:36652), stack: xfs_create → xfs_dir2_sf_to_block → xfs_bmap_btalloc → xfs_alloc_vextent_iterate_ags → mxfs_ag_dlm_lock_bounded → msleep.
- Cycles ALL 25 AGs, each 40×100ms then P5G-AGLOCK-BOUNDED-BUSY -EAGAIN, wrapping forever (observed 20+ min), while ALL 31 peers idle (their rsyncs done in 3-18s rc=0; they stalled at the coord barrier → NO_TERMINAL_RECORD=32).
- Violates the :36646 termination invariant ("sweep always reaches an AG this node holds cached — cannot come back empty-handed").
- CONTRADICTION: trylock path (mxfs_v5_dlm_ag_lock_nb v5_mount.c:5909 → mxfs_dlm_caw_lock NOQUEUE) reports peer-held for EVERY AG, yet BAST receivers fleet-wide print P12-AGBAST-RX holders=0 cached=0 (xfs_mxfs_dlm.c:41010) — no live node believes it holds them.
- Open hypothesis (NOT proven): on-disk CAW AG slots orphaned by a stale holder. Candidate contamination: the first failed clean-slate pass did `umount -l` on test4/6/18/19/21/22/26/27 before this board. Alternative: genuine release-path bug. CAW slot table on disk is the single truth — next step is reading the actual holder of a busy AG resource (mxfs_v5_dlm_ag_held helper exists; ag_strand_repair machinery from sess20 may be designed for exactly this stranded-AG case).
- test30 task is unkillable (kernel msleep loop, SIGKILL undeliverable); node needs virsh destroy/start AFTER evidence capture.

## Board state on .488 (chunked filtered runs — safe, marker-matched, no re-mkfs)
PASS: precond_readiness fio_perf fio_perf_vs_xfs cache_coherency strong_consistency posix_multi mmap_coherency zero_silent_loss dlm_fairness dlm_membership scaling_curve dlm_scaling.
FAIL: rsync_paired (above). Not yet run: crash_consistency dir_reuse_coherency fence_during_write fault_netpartition soak dirent_durability node_responsive kernel_health ag_strand_repair sustained_load dirent_publish_integrity dirent_type_integrity open_defects.
Chunking method: max_nodes=1 cells (posix_single fsx fio_verify integrity_filetypes fault_enospc) are inapplicable at 32 — the 32/caw board is 28 cells.

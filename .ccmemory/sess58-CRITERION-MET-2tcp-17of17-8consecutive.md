---
name: sess58-CRITERION-MET-2tcp-17of17-8consecutive
description: sess58 CRITERION MET: build 60EFBE5E = ./run.sh 2 tcp 17/17 × 8 consecutive clean-reboot runs (100%). Two roots fixed: create↔remove AG↔dir ABBA dead…
metadata:
  type: project
---

## sess58 (ccloop 8ddb16a2) — CRITERION "2 node dlm=tcp test 100% successful" MET

### RESULT: build 60EFBE5E23421FC56645074, `./run.sh 2 tcp` = **17/17 on 8 consecutive runs**, each with a fresh `virsh destroy/start test1 test2` + `reset2_tcp.sh` between. Logs: /tmp/suite_60ef_1.log … _8.log (all "17 PASS / 0 FAIL", ran=17, rc=0). Root-cause markers TDS-LEFTOVER=0, P58-DIRPIN-NONEX=0, P119-NONEX-FLUSH-SKIP=0, shutdown=0 in the verified runs (the only P36-RETRY seen = a single benign transient retry that succeeded, not a 30-60 deadlock storm). Criteria-met marker WRITTEN.

### TWO ROOT CAUSES PROVEN (RULE 4) + FIXED — both in xfs/xfs_inode.c:

**(1) create↔remove AG↔dir ABBA deadlock** (was the tcp_dlm_scaling within-window/shutdown failure). See [[sess58-FIX-create-remove-AG-dir-ABBA-deadlock]].
- xfs_create (xfs_dialloc first) + xfs_rename (mxfs_trans_preacquire_inode_ags) are AG→dir; xfs_remove was the lone dir→AG (xfs_trans_alloc_dir takes dir ILOCK before the iunlink AG).
- FIX: xfs_remove pre-acquires the child inode's AG DLM grant (standalone mxfs_ag_dlm_lock, released on success after commit + at out_parent on error) BEFORE xfs_trans_alloc_dir. All three ops now AG→dir → serialize on the AG, no ABBA.

**(2) durable dirent RESURRECTION** = xfs_ilock_nowait skips the DLM grant for ILOCK. See [[sess58-FIX-resurrection-lock-two-inodes-nowait-skips-dlm]].
- xfs_ilock_nowait (xfs_inode.c:296) acquires the DLM only for IOLOCK (atomic xfsaild/reclaim carve-out), NOT ILOCK. xfs_lock_two_inodes (remove/link) and xfs_lock_inodes (rename) take the AIL-contended inode via xfs_ilock_nowait → if it's a DIR it gets modified+committed at its STALE cached mode (NL/PR, ex_h=0) → P58-DIRPIN-NONEX → P119-NONEX-FLUSH-SKIP → peer reads stale → dirent resurrects (TDS-LEFTOVER). PROVEN by the P58 dump_stack (xfs_inode_item_pin <- xfs_trans_commit <- xfs_remove, and separately comm=mv for rename).
- FIX: in BOTH xfs_lock_two_inodes (~650) and xfs_lock_inodes (~585), when the nowait-locked inode is a DIRECTORY, acquire its DLM grant explicitly via mxfs_dlm_ilock_begin (released on the drop-and-retry path; balanced by the caller's xfs_iunlock). DIR-ONLY is essential: acquiring for files too (build F06293AE) went 12/17 (broad slowness + a pre-existing inobt-stale create double-alloc shutdown cascade). The remove fix alone got 2/3 (rename path still leaked, run3 comm=mv); adding the rename/lock_inodes fix → 8/8.

### KEPT diagnostics (cheap regression detectors): P58-DIRPIN-NONEX (xfs_inode_item.c, fires if a dir pins at non-EX), P58-AGSTATE (xfs_mxfs_dlm.c yield path). Unused infra left in tree: mxfs_dlm_lock_retries / mxfs_v5_dlm_inode_lock_retries (dlm.c/v5_mount.c) — a refuted periodic-yield attempt, harmless.

### Files changed: xfs/xfs_inode.c (remove AG pre-acquire + lock_two_inodes + lock_inodes dir-DLM), xfs/xfs_inode_item.c (P58 probe + includes), xfs/xfs_mxfs_dlm.c (P58-AGSTATE probe), dlm/dlm.c+dlm.h+v5_mount.c+v5_mount.h (unused retry-budget infra). tests/tcp/capture_agdeadlock.sh (new diagnostic harness).

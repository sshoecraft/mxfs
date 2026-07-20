---
name: sess58-FIX-resurrection-lock-two-inodes-nowait-skips-dlm
description: sess58 PROVEN FIX (build 1686FC03): resurrection root = xfs_ilock_nowait skips DLM for ILOCK; lock_two_inodes AIL-nowait branch modified the dir with…
metadata:
  type: project
---

## sess58 — PROVEN ROOT + FIX of the tcp_dlm_scaling durable dirent RESURRECTION

### ROOT (captured, RULE 4): xfs_lock_two_inodes nowait branch modifies the dir WITHOUT a DLM EX grant
P58-DIRPIN-NONEX probe (added at xfs_inode_item_pin) + its dump_stack PROVED it:
```
xfs_inode_item_pin   <- dir ino=17316994 pinned at dlm_mode=NL(0)/PR(3), ex_h=0
xfs_cil_prepare_item <- xlog_cil_commit <- __xfs_trans_commit
xfs_trans_commit
xfs_remove+0x313     <- xfs_remove commits the dirent removal with the PARENT DIR at NL/PR, ex_holders=0
```
`xfs_remove`/`xfs_rename`/`xfs_link` lock the two inodes via `xfs_lock_two_inodes` (xfs_inode.c:619). When ip0 (lower ino) is in the AIL, it locks ip1 (higher ino) via `xfs_ilock_nowait`. **`xfs_ilock_nowait` for ILOCK acquires ONLY the rwsem, NOT the DLM grant** — the DLM acquire is gated on `XFS_IOLOCK_*` only (the atomic xfsaild/reclaim carve-out; xfs_inode.c:296-302). So when the parent DIR is ip1 (its inode number > the child's — common under the rapid create/rm inode reuse), the dir is modified + committed at its STALE cached DLM mode (NL/PR, ex_holders=0) with NO exclusive authority. The committed dir change is then flush-skipped (P119-NONEX-FLUSH-SKIP i_dlm_mode=0 in_ail=1) and overlaid (P-CLMERGE) → the peer reads stale disk → the removed dirent RESURRECTS (node1 `TDS-LEFTOVER ino=DIR names=[n2_r132]`). Intermittent because it depends on dir-vs-child inode-number ordering + ip0-in-AIL.

### FIX (build 1686FC03C3142F4D7426F4F): acquire ip1's DLM grant in lock_two_inodes when ip1 is a DIR
In `xfs_lock_two_inodes` (xfs/xfs_inode.c ~650), the AIL-nowait branch: if `S_ISDIR(VFS_I(ip1))`, call `mxfs_dlm_ilock_begin(ip1, EX/PR)` before the nowait rwsem lock (undo with `mxfs_dlm_ilock_end` on the drop-and-retry path). DIR-ONLY is essential — the first attempt acquired the DLM for files too and went 12/17 (broad slowness + a pre-existing create double-alloc shutdown cascade). Process context always (safe to block); ascending ino (ip0<ip1, no DLM ABBA); an inode-DLM release drains only ip1 so no v0.3.148 AG-drain wedge; balanced by the caller's xfs_iunlock(ip1) -> mxfs_dlm_ilock_end.

### RESULT: clean `./run.sh 2 tcp` = **17/17 ONCE** (build 1686FC03, with the [[sess58-FIX-create-remove-AG-dir-ABBA-deadlock]] remove-fix). ALL tests pass incl tcp_dlm_scaling 2/2, dir_reuse 2/2, soak, fault_netpartition. CRITERION (reliable 100%) NOT yet confirmed — running reliability loop. Marker NOT written.

### REFUTED variant: acquiring ip1 DLM for ALL inodes (not dir-only) = 12/17 (build F06293AE) — too broad. Keep the S_ISDIR gate.

### Tree state: builds 1686FC03 = remove AG→dir fix (xfs_remove) + lock_two_inodes dir-DLM fix + P58/P58-AGSTATE diagnostics + unused mxfs_dlm_lock_retries infra. NEXT: reliability loop ≥5 clean reboot+suite runs; if all 17/17, write criteria-met marker.

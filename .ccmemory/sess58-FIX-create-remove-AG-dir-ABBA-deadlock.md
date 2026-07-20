---
name: sess58-FIX-create-remove-AG-dir-ABBA-deadlock
description: sess58 PROVEN FIX (build 456774D1): xfs_remove was the lone dir→AG op; create(dialloc)+rename(preacquire) are AG→dir. Made remove pre-acquire child A…
metadata:
  type: project
---

## sess58 (ccloop 8ddb16a2) — PROVEN ROOT + FIX of the tcp_dlm_scaling AG-deadlock

### ROOT (captured directly, RULE 4): create↔remove AG↔dir ABBA
`tcp_dlm_scaling` (= `repro_rename_drain` workload: each node create+mv+rm in a SHARED dir) has THREE pass conditions: mesh up, each node 150 rounds **within 60s**, dir drained to 0. The AG-deadlock fails the within-window + drain checks (NOT just the resurrection).

Captured cycle (P36-RETRY + new P58-AGSTATE probe):
- **test1** `P36-RETRY ino=0 type=3` = blocked acquiring **AG-0 EX**; holds dir-132 EX.
- **test2** `P36-RETRY ino=132 type=1` = blocked acquiring **dir-132 EX**; holds **AG-0** (`P58-AGSTATE ag=0 cached=0 bast_pending=1 holders=1`).
- It is a LIVELOCK (poll/retry loops, interruptible sleep — sysrq-w/-t show NOTHING; the threads aren't D-state). ~60s P36-RETRY storm → -ETIMEDOUT → dirty `xfs_trans_cancel:1061` "Corruption of in-memory data" SHUTDOWN.

The AG-0 holder is a **create's xfs_dialloc** (P137-IFREE-TIME=0 ruled out the inactivation path). Lock orders:
- **xfs_create**: `xfs_dialloc` (AG, line 1421) BEFORE dp ILOCK (line 1430) = **AG→dir** (v0.3.148 drop-ILOCK-across-dialloc made it so).
- **xfs_rename**: `mxfs_trans_preacquire_inode_ags` (4104) BEFORE `xfs_lock_inodes` (4116) = **AG→dir** (sess77).
- **xfs_remove**: `xfs_trans_alloc_dir` takes dp ILOCK (3676) BEFORE the iunlink AG acquire in `xfs_dir_remove_child` (3727) = **dir→AG**. ← THE LONE OUTLIER.

So a peer create (AG→dir) ABBA's with a remove (dir→AG) on the same dir+AG. sess57's "pre-lock ip AG before dir_remove_child" did NOT fix it — it pre-acquired the AG AFTER dp was already locked (still dir→AG).

### FIX (KEEP, build 456774D11180A1146ED6FB0): make xfs_remove AG→dir
In `xfs_remove` (xfs/xfs_inode.c), pre-acquire the child inode's AG DLM grant via standalone `mxfs_ag_dlm_lock(mp, p58_ag)` (perag = child's AG) BEFORE `xfs_trans_alloc_dir` takes dp ILOCK; release via standalone `mxfs_ag_dlm_unlock` on the success path (after commit+dir-durable flush) and at `out_parent` (all error paths). Mirrors the xfs_inactive_ifree standalone-AG pattern (~2507/2666): the in-trans iunlink/difree acquire nests on the fast path, the trans deferred-unlock balances, our standalone unlock is the last holder. Multi-node gated. Now ALL THREE ops are AG→dir → they serialize on AG-0 (acquired first), and the AG-0 holder always reaches the dir freely → no ABBA.

### VERIFIED: repro_rename_drain 150 8 → **4/4 runs ALL drained clean, P36=0, shutdown=0, P58-DIRPIN-NONEX=0** (was ~50% deadlock+shutdown, P36 storms of 30-59). The P58/NL-commit dir-pin-at-NL was a deadlock-TEARDOWN artifact (gone now), NOT a separate resurrection bug.

### Other this-session findings:
- P58-DIRPIN-NONEX probe added at xfs_inode_item_pin (xfs_inode_item.c): fires if a DIR commits/pins at i_dlm_mode != EX. Baseline (pre-deadlock) = 0 → the resurrection is NOT a commit-without-EX bug (it's post-commit flush/reload). KEEP as a detector.
- P58-AGSTATE probe in mxfs_dlm_yield_basted_cached_ags (xfs_mxfs_dlm.c): logs non-yieldable held/cached AGs. KEEP.
- Infra added (harmless, currently unused): mxfs_dlm_lock_retries / mxfs_v5_dlm_inode_lock_retries (dlm.c/v5_mount.c) — a periodic-yield-during-inode-poll attempt that did NOT fix it (the yield can't release a holders=1 AG); reverted the ilock_begin behavioral use, kept the functions.

### NEXT: run full `./run.sh 2 tcp` reliability loop. If tcp_dlm_scaling still fails it's the RESURRECTION (drain leftover, separate from this deadlock) — see [[sess57-FINAL-state-and-next-steps]] (ICLUSTER lock).

---
name: sess18run-FIX-noino-bast-offload-recv-thread-eliminates-60s-create-stall
description: sess18(ccloop) FIX (build 16A3B9C9, KEEP): offload NO_INODE BAST heavy-release off the TCP recv thread → eliminates 8/tcp dir_reuse 60s create-phase…
metadata:
  type: project
---

## sess18 (ccloop) — recv-thread BAST offload FIX (build 16A3B9C9606A6456B2D0091, KEEP)

### What was wrong (PROVEN, RULE 4)
8/tcp dir_reuse_coherency failed by SLOWNESS (300s TEST_TIMEOUT), not correctness. Timed the test phases (mxfs-DRCph markers): the **create phase stalled 60-69s on ~half the rounds** (verify/rm were fast). Root chain:
- dir_reuse rank1 `rm -rf` frees ~800 inodes/round; next round all 8 nodes REALLOCATE those same inode numbers (reuse) and publish EX.
- A reused inode's EX publish (deferred-publish worker, mxfs_v5_dlm_inode_lock, 60s budget) conflicted with the prior holder and timed out (rc=-110, P36-RETRY counts 59→0). The test's post-create `sync` blocked the full ~60s waiting for the inode to publish+checkpoint.
- ROOT of the 60s: the prior holder's BAST handler. `mxfs_dlm_bast_notify` (xfs_mxfs_dlm.c ~7642) NO_INODE path (inode reclaimed) does `xfs_log_force(SYNC)` + `xfs_ail_push_ag_sync_bounded` + `blkdev_issue_flush` + unlock — SYNCHRONOUSLY. And `mxfs_peer_recv_fn` (dlm/peer.c:154) dispatches msg_cb (incl. BAST) INLINE on the per-peer TCP recv thread. So ~800 reused-inode releases/round serialized on the recv thread (each ~75ms) → ~60s stall blocking the whole DLM message stream. (The IN-CACHE BAST path already runs async on m_mxfs_inode_bast_wq; only NO_INODE was synchronous.)

### THE FIX (KEEP)
In `mxfs_dlm_bast_notify` NO_INODE path: offload the heavy release (log-force + AG-drain + flush + publish_unpublished + on-disk unlock) to `m_mxfs_inode_bast_wq` (WQ_UNBOUND, multi-threaded) via a new `struct mxfs_noino_bast_work` + `mxfs_dlm_noino_bast_work_fn`. Recv thread stays responsive; drains run concurrently. Correctness preserved (drain still BEFORE unlock, invariant #1). Falls back to inline on kmalloc/queue failure. Added just above mxfs_dlm_bast_notify (~line 7621).

### RESULT (mht=300 and mht=250 both CORRECT now)
- create-done dropped 64s → ~5s; **rc110=0** (60s stalls GONE).
- **failrounds=0** (data CORRECT) at mht=300 AND mht=250. (mht=150 still loses data: readdir 701/800 persistent + 2 leaf holes — the low-mht data-block lost-update is a SEPARATE residual.)
- BUT still ~13-14s/round → 24 rounds ≈ 320s > 300s TEST_TIMEOUT. mht=300 reached round 22; mht=250 reached round 23 (failrounds=0). SO CLOSE.

### NEW residual blocker = rm/inactivation TAIL
rank1's `rm -rf 800 files; sync` is USUALLY 0-1s but OCCASIONALLY 60-121s (e.g. round 23 = 121s killed the budget). rank1 rc110=0, no big non-dir P34 → not a single DLM timeout; it's 800 serial reused-inode inactivations (each EX-acquire BASTs the creator + the holder's heavy bast_process drain) and/or the `sync` forcing a backlog. ALL nodes wait at the cl-barrier for rank1's rm → 121s stalls everyone. NEXT: cheapen the per-inode release for REGULAR FILES (bast_process at ~5650 does log_force+drain+FUA per inode; a freed/clean regular file needs no heavy drain — only DIRS need the sess88 dir-data drain), OR batch/parallelize the inactivation. Also consider: holder doesn't know the inode is being freed (wasted flush of soon-deleted file).

### MUST VERIFY: no regression on 1/2/4 tcp (the offload touches a shared path). Test ./run.sh 2 tcp and 4 tcp before declaring. See [[sess17run-STATE-3of4-criterion-pass-8tcp-residual-leafhash-plus-contention]].

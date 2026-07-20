---
name: sess7-ccloop-8node-progress-ABBA-fixed-now-leaked-ilock-rm
description: sess7(run6614) 8/tcp: drain_evict ABBA fix (638E5829) cut mass-loss 700→797/800. Residual wedge = LEAKED i_lock(write) on shared dir by rm (xfs_lock_…
metadata:
  type: project
---

## sess7 (run 6614) — 8/tcp dir_reuse: BIG progress + newly-exposed leak

### PROGRESS: drain_evict ABBA fix (build 638E582919B7D49E) works
`mxfs_dir_drain_evict_data_blocks` blocking `down_read(&i_lock)` at 7856 → bounded trylock (50×2ms then return 1=skipped). Result: the dominant 8-node mass-loss (readdir **700/800** = a whole node's 100 entries missing because the node hung) is GONE — last-failround now `readdir=797/800` on all nodes = only the fine scattered ~3-dirent residual. This fix is KEEP.

### RESIDUAL WEDGE (now dominant): LEAKED i_lock(write) on the shared dir
After the drain_evict fix, dd gets PAST drain_evict but wedges at the plain `xfs_ilock(SHARED)` in `mxfs_dlm_dir_consumer_refresh` (xfs_mxfs_dlm.c:5309) → `down_read(&i_lock)`; the BAST release worker wedges at `mxfs_dlm_bast_process → mxfs_drain_ilock_read → msleep` (waits forever, only bails on FS shutdown). Both on the SAME dir ino=131.
**DECISIVE forensic (P132-ILOCK-STUCK, always-on):** `ino=131 waited_ms=270000 rd_held=0 cnt=3 wr_last=xfs_lock_two_inodes+0x14e pid=17267 comm=rm`. rwsem `count=3` = WRITER_LOCKED|WAITERS bit set; recorded writer pid 17267 (`rm`, the rank1 rm-rf) is GONE from ps. ⇒ a genuinely LEAKED write lock: `rm` exited/was-killed while holding the dir ILOCK_EXCL taken via `xfs_lock_two_inodes` (xfs_inode.c:643, called by xfs_trans_alloc_dir in xfs_remove). The leak is PRE-EXISTING — my drain_evict fix only unmasked it (baseline hung in drain_evict BEFORE reaching this point). Once i_lock is leaked, the release-drain can't complete → the dir's DLM grant never hands off → peers wanting the dir cascade-wedge → whole test fails.

### LEAK not yet pinned (static reads of xfs_remove/xfs_lock_two_inodes show balanced unlock paths). Hypotheses to test next (RULE 4):
1. rm SIGKILLed by harness mid-xfs_remove during an FS shutdown race → an mxfs error/shutdown path skips xfs_iunlock(dp). We DID see rc!=0 DLM-acquire shutdowns (xfs_mxfs_dlm.c:15597) + xfs_create/remove shutdown faces same runs.
2. A double-down_write on dp (an mxfs hook on the remove path — e.g. mxfs_dlm_dir_modify_refresh@xfs_inode.c:3866, or mxfs_dlm_ilock_begin(ip1) at xfs_lock_two_inodes:698) unbalanced vs a single up_write → write bit stays set after the "unlock".
NEXT: instrument every xfs_remove exit + a per-syscall down_write/up_write balance check on dir inodes to catch the unbalanced path; OR add dead-writer recovery to mxfs_drain_ilock_read (risky: can't safely steal an rwsem unless owner provably dead via task_struct, not pid).

### Also applied this session: consumer_refresh (5309) blocking xfs_ilock(SHARED)→ bounded down_read_trylock+bail (loss-safe) so the READER (dd) no longer wedges on a contended/leaked i_lock. (build after 638E5829.)
### Reverted earlier this session (do NOT retry): candidate-A (hgg==0 gg_refresh arm → drain_evict hang), candidate-B (durable_signal per-create publish → rc=-110 acquire-timeout shutdown). See [[sess7-ccloop-DECISIVE-8node-ABBA-deadlock-drain-evict-ilock]].

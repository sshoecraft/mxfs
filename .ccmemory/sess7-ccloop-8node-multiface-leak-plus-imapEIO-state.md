---
name: sess7-ccloop-8node-multiface-leak-plus-imapEIO-state
description: sess7(run6614) HEAD=F5A90E91 (pristine baseline + leak-attribution instr, behavior-neutral). 8/tcp dir_reuse has 2 hard faces: (1) leaked i_lock hang…
metadata:
  type: project
---

## sess7 (run 6614) — 8/tcp dir_reuse: two distinct hard faces, code back at baseline

### CURRENT BUILD: F5A90E91C5841F8B (= pristine baseline behavior + leak-attribution instrumentation only; behavior-neutral). All sess7 workarounds REVERTED (see why below). Marker NOT written.

### KEY LESSON: the drain_evict / consumer_refresh trylock-SKIP workarounds REGRESS 4-node (12/12 → 0/4).
- The 8-node drain_evict `down_read(&i_lock)` HANG is NOT a live-thread ABBA — it blocks on a LEAKED i_lock (see face 1). Converting it to bounded-trylock-then-SKIP only unwedged the node by skipping the coherence-critical dir-block evict → at 4-node (no leak) it FALSE-SKIPS transient-writer contention → stale-base RMW → dirent loss → 0/4. Same for the consumer_refresh(5309) skip. **DO NOT reintroduce trylock-skip on these paths.** The real root (leak) must be fixed so the blocking down_read never wedges.

### FACE 1 — LEAKED i_lock(write) on shared dir (hang). (~1/3 of runs)
`P132-ILOCK-STUCK ino=131 cnt=3 (WRITER_LOCKED|WAITERS) rd_held=0 wr_last=xfs_lock_two_inodes pid=rm(dead)`. dd (consumer_refresh→xfs_ilock) + bast release worker (mxfs_drain_ilock_read, waits forever) both wedge → grant never hands off → peers cascade. Root: an rm/xfs_remove exited holding the dir ILOCK_EXCL. UNPINNED — all obvious lock sites (xfs_remove gotos, xfs_trans_alloc_dir, xfs_lock_two_inodes, reload@12471, reset_inode@13667, sf_merge@13985) verified balanced. **NOTE: raw down_write sites were previously UNattributed (mxfs_ilk_note_lock only ran in xfs_ilock); sess7 ADDED note_lock to all 3 raw sites (12471/13667/13985) so the NEXT P132 that fires names the true leaker. The instrumented run did not hit face 1 — RE-RUN drc_reliability 8 until a P132 fires, then read wr_last.**

### FACE 2 — imap_to_bp rc=-5 on reused dir → create-fail → shutdown (dominant in the F5A90E91 2-run). (all 8 nodes shut down, readdir=0/800)
Faces: `DLM inode reload imap_to_bp failed ino=131 rc=-5` (the DIR itself, freed+realloc'd every round) + file inos → `P-CREATE-ERR2 dir_create_child err=-5 t_dfops_empty=1 dp_ino=131` → `XFS Metadata I/O Error (0x1) at xfs_trans_read_buf_map (xfs_trans_buf.c:313) Shutting down`. Root: the reload (xfs_mxfs_dlm.c:11799) stales the dir's inode-cluster buffer then xfs_imap_to_bp re-reads DURING the free/realloc window → transient EIO; the reload just logs+returns, but the CREATE path (xfs_create/dir_create_child) hits the same EIO reading dp's cluster, fails -5 on a dirtying transaction → shutdown. FIX IDEA (untested): bounded RETRY of xfs_imap_to_bp on -EIO in the reload AND/OR in the create's dp cluster read (the reuse window is sub-ms; sess9@3439 already notes 'transient xfs_imap_to_bp failure' and retries in the durable path — mirror that here). Must NOT let a transient reuse-window EIO dirty-cancel→shutdown.

### NEXT SESSION PLAN (RULE 4):
1. Confirm F5A90E91 does NOT regress 1/2/4 tcp (behavior-neutral instr — expected 4/tcp=12/12).
2. Pin FACE 1: re-run drc_reliability 8 until P132 fires; read wr_last (now correctly attributed) → fix the actual leaking down_write path.
3. Fix FACE 2: bounded xfs_imap_to_bp EIO retry on the reused-dir reload+create path (make transient reuse-window EIO non-fatal, no dirty-cancel shutdown).
Both faces must be fixed for 8/tcp. See [[sess7-ccloop-DECISIVE-8node-ABBA-deadlock-drain-evict-ilock]] [[sess7-ccloop-8node-progress-ABBA-fixed-now-leaked-ilock-rm]] [[sess6-ccloop-8node-dirreuse-inode-reuse-cascade-faces]].

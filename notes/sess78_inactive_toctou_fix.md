# sess78 — xfs_inactive TOCTOU double-free fix (Gemini RULE-5 design)

## Proven diagnosis (instrumented)
- `cache_coherency` PASSES 4/4 with build `68DF68548A03059ED1292A6` (sess37
  pinned-drain fix deployed). `rsync_paired` FAILS: reliably reproduces the
  bnobt double-free `ltbno+ltlen>bno` at xfs_alloc.c:2244 (xfs_free_ag_extent
  → xfs_defer_finish_noroll → shutdown).
- The sess37 pinned-drain fix path **never fires** under rsync (P73-FIX=0 on
  all nodes) → it is NOT the mechanism for this corruption.
- P47-INACT verdict: `inact_ino=131 incore_gen=G disk_di_mode=00 disk_di_gen=G+1
  verdict=DISK-FREE`. A node runs destructive inactivation on a stale in-core
  inode while a peer has already freed+reused it.
- The sess47 xfs_inactive guard (FUA-read disk dinode; skip if di_mode==0 or
  gen-mismatch) FIRES correctly (INACT-SKIP-STALE 14/5/4×) but has a **TOCTOU
  window**: 2 double-frees slipped through. The guard read happens at the TOP
  of xfs_inactive; between it and `xfs_free_ag_extent` a peer (which also holds
  the inode in-core with nlink==0) frees+reuses the inode. Two nodes race into
  destructive inactivation; the guard's point-in-time read can't close it.

## Fix (Gemini design, RULE 5)
Make the disk-check + destructive free atomic w.r.t. the cluster by acquiring
the per-inode DLM **EX** grant at the top of xfs_inactive (multi-node, nlink==0
branch), BEFORE the disk read, and holding it across truncate+ifree.

Key points:
1. **DLM → ILOCK order**: xfs_inactive runs from the inodegc worker with NO XFS
   ILOCK held. Acquire DLM EX first; let truncate/ifree take ILOCK internally.
   This matches the safe hierarchy DLM→ILOCK→AGI-buf and cannot deadlock vs the
   documented ILOCK-across-CAW-poll holders.
2. **Use the LOW-LEVEL lock** `mxfs_v5_dlm_inode_lock(dlm, ino, MXFS_LOCK_EX)` /
   `mxfs_v5_dlm_inode_unlock(dlm, ino)` — NOT `mxfs_dlm_ilock_begin`, which
   reloads/mutates the VFS struct inode. The inode is in I_FREEING during
   eviction; reloading it (a peer may have reused the ino as a different type)
   would corrupt teardown and trip VFS asserts. We only need cluster mutex + a
   raw FUA disk read into local vars.
3. **Serialization correctness**: winner frees under EX → ifree commits disk
   mode=0; transferring EX to the loser forces the winner's flush (CAW EX
   acquire BASTs peers + flush), so the loser's post-acquire FUA read observes
   di_mode==0 and skips. Exactly-once destructive inactivation. Whichever node
   wins the EX race does the (single) free with the correct same-incarnation
   extent map.
4. **Idempotent unlock**: mxfs_dlm_caw_unlock returns 0 on -ENOENT and only
   clears our holder bit → acquire/release pair is safe even if the inode was
   otherwise held; release at the single `out:` label gated by a bool.

## Rejected alternatives
- Ownership token (only unlinker inactivates): risks stranding the inode on the
  AGI unlinked list if the unlinker crashes/evicts before inodegc → leak.
- AGI-unlinked-list coordination under AGI buffer lock across truncate: violates
  XFS buffer locking rules, wedges the AG.

## Implementation
`xfs/xfs_inode.c` xfs_inactive(): add `bool mxfs_inact_dlm_locked`; acquire EX
before the sess47 disk-read guard; release at `out:`.

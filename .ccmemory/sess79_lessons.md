---
name: sess79_lessons
description: "sess79 (ccloop run, 2026-06-04, DATED) — at the time the blocker was cache_coherency not rsync_paired (cache_coherency RESOLVED at sess130; 17/17 criteria pass at ≤8 nodes as of 2026-07-08); Priority-1 deterministic reg-file BAST-release flush landed (cross_write_read writer-durability), rsync preserved; bnobt double-free during unlink was then critical path."
metadata: 
  node_type: memory
  type: project
  originSessionId: ef940f06-c2b0-474a-a230-c7e71a723a05
---

# sess79 lessons (ccloop run 29df431e, 2026-06-04)

**Resume framing was STALE.** The ccloop resume said "sole failing criterion is
rsync_paired (615%→need ≤120%)". WRONG by the time I started: the current full
source tree compiles to **F7BEB353** (forced rebuild confirmed: node-affine dir
alloc + sess77 deadlock fixes + deferred-publish + dir_unpub_skip all present),
and on that build `.criteria_results.json` showed **rsync_paired PASS 105%** but
**cache_coherency FAIL (passed=1-2 failed=2-3)**. So the real blocker is
**cache_coherency**. Always trust `.criteria_results.json` + a fresh run over the
resume narrative.

## RULE-4 isolation done
- `dir_unpub_skip=0` (dir-FUA-skip OFF) vs `=1`: cache_coherency fails IDENTICALLY
  → the dir-skip is NOT the coherency culprit. Leave dir_unpub_skip default (1).

## cache_coherency current failure profile (build F7BEB353, default params)
- test_cross_visibility: **PASS** (reliable).
- test_rename_visibility: **FAIL ~40/240** — reader-side stale cached dir DATA/LEAF
  block (concurrent shared-dir rename; peer's renamed-to name invisible / content
  empty). NO corruption. Flaky (passed once).
- test_unlink_visibility: **FAIL 5-52/122** — phantom readdir (stale cached dir
  DATA block lists deleted names; stat/lookup correctly ENOENT) **AND triggers an
  FS SHUTDOWN**: `Internal error ltbno+ltlen>bno at xfs_alloc.c:2244, caller
  xfs_free_ag_extent ← xfs_defer_finish` = the recurring **bnobt double-free**
  (concurrent shared-dir unlink frees a dir/inode block a peer already freed; a
  stale cached AG view). Preceded by INODE-REUSE-EVICT. This is the deep AG-coherency
  wall (sess42-47,52). sess47/78 guard (xfs_inode.c ~1944 xfs_inactive) covers
  regular-inode inactivation double-free but NOT this defer-finish path (likely a
  DIRECTORY-block double-free during concurrent unlink).
- test_cross_write_read: di_size=0 empty small-file read. **CANNOT RUN in the full
  criterion** because unlink_visibility (run just before it) shuts node1 down →
  "Node 1 not mounted" → cwr counted as failed. ⇒ **must fix the unlink bnobt
  shutdown before cwr's verdict is even observable in the criterion.**

## WIN landed this session (build DA1CF4D8, KEEP)
**Priority-1 (Gemini RULE-5 design): deterministic reg-file durability on BAST
release.** In `mxfs_dlm_bast_process` (xfs/xfs_mxfs_dlm.c ~L1249, S_ISREG &&
mxfs_reg_release_durable) replaced the non-deterministic 50×/100ms (log_force +
xfs_ail_push_ag_sync — xfsaild uses trylock, skipped under load → released with
disk di_size=0 → peer reads empty) with:
  early-out if (!in_ail && !pinned) [already durable] →
  else loop≤8: xfs_log_force(SYNC) [unpin] → xfs_imap_to_bp [lock cluster buf] →
  xfs_iflush_cluster(bp) [copy in-core di_size INTO buffer] → xfs_bwrite(bp)
  [synchronous in-place write] ; then blkdev_issue_flush.
Result: **P-REG-DURABLE-FAIL detector = 0 on all nodes** (writer durability now
solid); cross_write_read PASSES in isolation (fresh single run).
**CRITICAL gotcha:** v1 (A8A048F5) did xfs_log_force(SYNC) UNCONDITIONALLY first →
regressed rsync_paired 105%→137% (node-private clean releases paid a full sync
flush). Fix = the already-durable early-out (skip log_force/iflush when !in_ail &&
!pinned). v2 (DA1CF4D8): **rsync_paired PASS 103%**, durability kept. The early-out
is load-bearing — never remove it.

## NEXT (critical path order)
1. **Fix the unlink bnobt double-free SHUTDOWN** (blocks cwr in the criterion).
   Instrument WHICH free is double (dir-block vs inode-block) during concurrent
   unlink; the defer-finish path is not covered by the sess47 inactive guard.
2. Then **dir-block reader staleness** (rename + unlink phantom readdir): Gemini
   Priority-2 = generalize the HB evict-ring to carry "dir D modified" (the ring
   plumbing ALREADY EXISTS: producer mxfs_disklock_note_freed / consumer evict_cb /
   mxfs_dlm_evict_inode_cb / XFS_ISTALE_CAW are wired for inode-FREE — extend the
   entry type to MXFS_INV_DIR and add a dir-block-invalidation consumer). KEY
   INSIGHT: the pin-skip wall (sess75, can't clear XBF_DONE on pinned buf) is a
   WRITER problem; a peer-modify invalidation targets the READER's CLEAN cached
   dir block → safe to invalidate. 2s HB cadence + test's sleep-2-after-barrier
   should be in time.

## ENV / mechanics
- Reset: `MKFS_OPTS=-f bash tests/reset4.sh 4`. If wedged (module refcnt stuck after
  a killed run; node ssh hangs): `LIBVIRT_DEFAULT_URI=qemu:///system virsh destroy
  testN; virsh start testN` for ALL 4, wait ~90s for NFS, reset4. (Did this once.)
- reset4 (~480-540s) + a criterion run exceeds the 600s foreground cap → run them
  as SEPARATE background tasks, wait for the task-completion notification.
- run_tests.sh / criterion stdout is BUFFERED when backgrounded — greps often see
  nothing mid-run; wait for completion then read /tmp/claude-1000/cache_coherency.*.log
  (criterion writes its own log path in the RESULT line).
- Build: `make modules` (touch changed .c if srcversion looks stale). Deploy = reset4.

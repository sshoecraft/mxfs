---
name: sess83_lessons
description: "sess83 (ccloop, 2026-06-04) — PROVEN the block-format-dir durable lost-update ROOT = the noino BAST path: a shared dir inode gets RECLAIMED mid-run, then a peer's BAST hits mxfs_dlm_bast_notify's no-inode branch → direct DLM unlock with NO dir-data durability drain → peer FUA-reads stale disk and clobbers committed dirents. FIX in mxfs_dlm_evict (reclaim path): drain dir data blocks durable before unlock (EXTENTS dirs). Build F08CE615 deployed test1-4, KEEP. REMAINING: shortform (LOCAL) barrier dirs still lose entries + slowness (bast_process ail_push_ag_sync per handoff)."
metadata:
  node_type: memory
  type: project
  originSessionId: 46b10855-2f89-4a75-ae83-22f6642e1597
---

# sess83 lessons (ccloop run 29df431e, 2026-06-04)

## BIGGEST WIN: PROVEN the block-format-dir durable lost-update root = the noino BAST path
RULE-4 loop, fully proven (not guessed):
- The dir-coherency code is sound on the bast_process handoff path: I added an
  always-on detector **P-DIRREL-DIFFERS** (in bast_process, AFTER the dir
  durability drain, FUA-read each dir block + whole-block memcmp vs in-core —
  clean compare since blocks were just bwritten, same LSN). Result **0 across a
  full run** → when a dir releases via bast_process, its blocks ARE durable.
  Release-side durability via bast_process is SOUND. P-SF-DURABLE-FAIL also 0.
- BUT the always-on DLM stats showed `bast: noino=2..12` per node. **noino** =
  `mxfs_dlm_bast_notify` got a BAST for an inode NOT in the in-core cache
  (xfs_iget INCORE → -ENOENT) → it does a DIRECT `mxfs_v5_dlm_inode_unlock`
  with NO durability drain (xfs_mxfs_dlm.c ~L1600).
- **PROOF (detector P-NOINO-BAST, always-on, logs ino+req_mode at that branch):
  the SHARED TEST DIR inode hits noino** — stat'd the dir inode (e.g. 2097281),
  grepped dmesg: test1 had 4 hits on the dir inode, test4 had 1. So the shared
  120-entry dir is RECLAIMED from cache mid-run; a peer's later BAST hits the
  no-drain direct-unlock.
- Gemini (RULE 5, fresh data) confirmed 100%: `xfs_reclaim_inode` reaches
  `mxfs_dlm_evict` once the inode CORE is clean (xfs_inode_clean) + unpinned,
  but a DIRECTORY's data-fork block buffers (dir DATA/leaf/free) are independent
  xfs_buf's tracked only in the AIL — reclaim's xfs_iflush writes the inode
  CLUSTER, NOT those. So evict releases the DLM with dir blocks still dirty →
  peer FUA-reads stale → clobbers committed dirents = the 90/120 "node lost its
  OWN files" durable lost-update.

## THE FIX (build F642835A→F08CE615, deployed test1-4, KEEP)
In `mxfs_dlm_evict` (xfs_mxfs_dlm.c ~L3107, the xfs_reclaim_inode hook at
xfs_icache.c:1565), BEFORE `mxfs_v5_dlm_inode_unlock`, for multi-node
S_ISDIR EXTENTS-format inodes holding a lock:
```
xfs_log_force(mp, XFS_LOG_SYNC);   // clear CIL pins so bwrite wait_unpin can't hang
mxfs_dir_flush_data_blocks(ip);    // sess82 helper: per-dir-block pin+lock+xfs_bwrite (targeted, NOT whole-AG)
blkdev_issue_flush(mp->m_ddev_targp->bt_bdev);
```
- We ALREADY hold XFS_ILOCK_EXCL here (== `ip->i_lock` rwsem, taken by
  xfs_reclaim_inode L1530) so extent list is stable — MUST NOT re-take i_lock
  (down_read would self-deadlock; XFS_ILOCK IS the i_lock rwsem, xfs_inode.h:49).
- Targeted per-block bwrite (Gemini: O(dir size) not O(AG dirty state); whole-AG
  ail_push_ag_sync deadlocks — sess82). 0 dir-flush errors, P-DIRREL-DIFFERS=0.
- Result so far: after delete phase the 120-entry test dir is cleanly 0/0 on all
  4 nodes (weakly positive the block-format loss is fixed) — but the test still
  TIMES OUT (see remaining), so NOT yet confirmed via a clean pass.

## REMAINING BLOCKERS (test still times out at 280s, cache_coherency still FAIL)
1. **SHORTFORM (LOCAL) dir lost-update — separate surface, NOT fixed.** The
   test's file-based barriers live in shared dirs `.mxfs_barriers/<name>/nodeN`
   (4 entries = shortform/LOCAL, entries inline in the dinode). Post-run, ALL 4
   nodes consistently see node2,node3,node4 but NOT **node1** (test1) — including
   test1's own view → node1's entries DURABLY missing (identical cross-node view
   = on-disk state, not per-node cache). My EXTENTS-only evict fix does NOT touch
   LOCAL dirs (their data IS the dinode; a dirty shortform dinode is NOT
   reclaimable per xfs_inode_clean, so noino-on-clean-shortform should be
   harmless — mechanism for the loss is UNRESOLVED; could also be test1 exited
   early on its own create/delete failure: barrier_wait RETURNS 1 on timeout and
   the test CONTINUES, so a node can fall out of sync. barrier_wait =
   tests/lib/cluster.sh:227, per-barrier MXFS_BARRIER_TIMEOUT).
   NEXT: minimal shortform reproducer (4 nodes touch one file each in a shared
   shortform dir, FUA-count dirents on disk) to isolate shortform vs block; and
   check whether test1 actually test_fail'd early (raise wrapper timeout to read
   the result, or capture per-node logs before timeout kill).
2. **SLOWNESS.** Gemini: bast_process's dir drain loop does `xfs_log_force(SYNC)
   + xfs_ail_push_ag_sync(d_agno)` (+ whole-AG mxfs_dir_push_data_ags) EACH of
   ~100 rounds, per handoff (~70 handoffs) = catastrophic. Replace with the same
   targeted `mxfs_dir_flush_data_blocks` (+ a dinode flush for the inode-clean
   wait). NOT done — do ONE change at a time; do after shortform fix so a clean
   pass is visible. (xfs_mxfs_dlm.c ~L1196-1202.)

## Build / detectors (all instr=0-safe, always-on, KEEP)
- **F08CE615** = P-DIRREL-DIFFERS (bast_process FUA dir-block compare) +
  P-NOINO-BAST (no-inode BAST ino logger) + the mxfs_dlm_evict dir-data-drain
  fix. instr currently 0 on nodes (INSTR_OPTS via reset4 did NOT propagate —
  set via `echo 1 > /sys/module/mxfs/parameters/instr` per node if needed).
- Markers P-SF-DURABLE / "BAST set stale" are mxfs_idbg (INSTR-GATED) — their
  absence at instr=0 is an ARTIFACT, not evidence (cost me a wrong "smoking gun";
  trust only always-on pr_warn markers + the report_stats line `DLM cache: ...
  bast: imm/def/noino`).

## Infra (reconfirmed)
- Nodes = test1-4 (MXFS_HOST_OFFSET=0). cache_coherency.sh sets
  MXFS_NODE_OFFSET=16 (test-LOGIC node-ids 17-20) but hosts stay test1-4 via
  get_node_hostname using MXFS_HOST_OFFSET (cluster.sh:14). test17-20 are DOWN.
- /src is NFS-mounted on nodes from 192.168.1.4:/src (export IS up this run);
  new mxfs.ko visible immediately at /src/mxfs/mxfs.ko.
- Deploy: rmmod+umount all nodes, then `bash tests/reset4.sh 4`. A wedged node
  (umount busy + fuser hangs) → `sudo virsh reset testN`, wait ~80s.
- instr=1 makes the test ~100x slower → it can't even reach the create storm in
  280s; detectors MUST be always-on and run at instr=0.

State head = sess83. See [[sess82_lessons]] [[sess80_lessons]] [[sess53_lessons]].

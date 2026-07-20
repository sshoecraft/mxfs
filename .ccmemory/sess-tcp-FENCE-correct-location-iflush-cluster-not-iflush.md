---
name: sess-tcp-FENCE-correct-location-iflush-cluster-not-iflush
description: IMPL REFINEMENT: the stale-dir-fork flush fence must go in xfs_iflush_cluster (xfs_inode.c:5325, before xfs_iflush@5470) NOT in xfs_iflush (erroring…
metadata:
  type: project
---

## Correct implementation location for the inode-fork-flush fence (refines [[sess-tcp-FIX-entrypoints-inode-flush-fence]])

### DO NOT fence inside xfs_iflush (xfs/xfs_inode.c:4298):
Returning an error from xfs_iflush causes xfs_iflush_cluster (its only caller) to ABORT the whole cluster flush and FORCE-SHUTDOWN the FS. xfs_iflush has no safe "skip just this inode" return. (My P-DIRIFLUSH detector lives there — fine for LOGGING, wrong for enforcement.)

### CORRECT fence point: xfs_iflush_cluster (xfs/xfs_inode.c:5325), at inode selection BEFORE `error = xfs_iflush(ip, bp);` (line ~5470).
- Skip the stale dir inode (don't add it to the cluster flush; leave it dirty/in-AIL) when its in-core block0 fsb is NOT canonical (divergent from on-disk / fork epoch stale). xfs_iflush_cluster already has per-inode skip logic (XFS_ISTALE, lock failures) — add an mxfs guard alongside.
- CRITICAL ADVANTAGE: xfs_iflush_cluster is the COMMON path for BOTH (a) the background AIL push AND (b) the EX release-drain (mxfs_dlm_dir_inode_durable → mxfs_inode_cluster_durable → imap_to_bp → xfs_iflush_cluster → bwrite). Since the stale flush is UNDER EX via the release-drain ([[sess-tcp-FINDING-stale-iflush-is-under-EX-not-NL]]), fencing here covers the actual failing path.
- PAIR WITH RELOAD: skipping a stale fork flush must trigger/leave a reload (i_dlm_stale) so the inode reconciles to the canonical fork before its next use — else the dirty stale inode lingers in the AIL forever (wedge). The reload must get node1's canonical block0 (fsb=15/daddr 120), not node2's self-stale disk image.

### Also available: xfs_inode_item_push (xfs/xfs_inode_item.c:740) — the AIL push iop. Returns XFS_ITEM_PINNED/FLUSHING/LOCKED to DEFER safely. Could return XFS_ITEM_LOCKED for a stale dir inode to defer the AIL-driven flush (but does NOT cover the release-drain path — so xfs_iflush_cluster is the more complete point).

### REVIEW FIRST: mxfs_iflush_cluster_merge_dirs(bp) at xfs/xfs_inode.c:5071 (called @5518 after the cluster flush). There is ALREADY a dir-merge-during-iflush mechanism — understand what it does (it may be the right place to RECONCILE the fork to canonical instead of fencing, or it may itself be writing the stale fork). Comment @5041 mentions "writes the WHOLE cluster, carrying this node's STALE [fork]".

Build at handoff: AFE4E833 (clean; P-GROW0 + P-DIRIFLUSH detectors, gated dirwr/instr). Marker NOT written. [[sess-tcp-FIX-DESIGN-fence-stale-dir-inode-fork-flush]] [[sess-tcp-P-DIRIFLUSH-detector-build-AFE4E833]]

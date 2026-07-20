---
name: sess-tcp-FAST-REPRO-wedge-and-classification
description: FAST REPRO of the deep wedge (build AFC07F4D): two nodes each do 3000 create+unlink in ONE shared dir → a node's FS shuts down in ~seconds (xfs_inact…
metadata:
  type: project
---

## FAST REPRO (build AFC07F4D, much faster than the full suite)
On a clean 2-node tcp cluster (slots 0/1), run on BOTH nodes concurrently:
```
D=/mnt/shared/.wedge; mkdir -p $D
for i in $(seq 1 3000); do : > $D/t${RANK}_$i; rm -f $D/t${RANK}_$i; done
```
(each node uses its own t1_*/t2_* names in the SAME shared dir). test2 FS shut down in ~seconds:
`xfs_inactive_ifree → Metadata I/O Error (xfs_inode.c:2374) Shutting down` + 112
`INACT-SKIP-STALE` hits, in test2's OWN affine **AG1** (slot1→AG1). PURE METADATA churn — no
data writes needed. So the wedge is NOT data-block-over-inode-cluster.

## Shutdown classification (the inodes that PASS the skip-guard and crash xfs_ifree)
`P19-B3DEC ino=209xxxx agno=1 incore_gen=G disk_mode=0100644 disk_gen=G coh_nlink=0
 local_unlink=0 dlm_mode=0 will_skip=0 (b1_diskfree=0 b2_genmis=0 b3_tornlive=0)` — i.e.
disk says LIVE, gen MATCHES, but this node is inactivating an inode it did NOT unlink
(local_unlink=0) and holds NO DLM lock on (dlm_mode=0). = sess111 "DISK-LIVE-same-gen =>
A-lost-removal" class. The skipped ones (caught by guard) are disk_mode=00 "disk-free".
=> Two faces in AG1: (a) inodes already freed on disk (disk_mode=00, guard skips), (b) inodes
disk-live-same-gen with local_unlink=0/dlm_mode=0 that proceed to xfs_ifree → eventually one
hits inobt corruption -117 → shutdown.

## Why local_unlink=0 / dlm_mode=0 during a create+unlink storm?
Suspicious: test2 creates+unlinks its OWN t2_* (should be local_unlink=1). The flood of
local_unlink=0/dlm_mode=0 inactivations = test2 inactivating inodes via a NON-local path —
likely incore iunlink-list recovery ("Found unrecovered unlinked inode") churning during the
storm, OR reclaim of peer-side / stale inodes. Next: instrument WHO queues these inactivations
(reclaim vs iunlink-recovery) and WHY a disk-live-same-gen inode with no local unlink is being
freed. The skip-guard (xfs_inode.c:2785) only covers disk-free/gen-mismatch/torn — it does NOT
cover "disk-live-same-gen but not-locally-unlinked + no-lock", which is the one that shuts down.

## NEXT SESSION fix direction
1. Use this fast repro (seconds, not 8-min suite).
2. Classify with P47-INACT (already live) at the shutdown; confirm A-lost-removal.
3. Root: a node inactivating/freeing an inode it neither unlinked nor locked = the inode-recycle/
   iunlink coherency. Likely the incore iunlink list carries stale entries across the rapid
   recycle. Consider: extend the skip-guard to also skip inactivation when local_unlink=0 AND
   dlm_mode=0 (this node has no business freeing it) — but verify that's not masking a real leak.
   Better: fix WHY these enter the inactivation queue.
Cluster: test2 wedged by this repro → reset needed. See
[[sess-tcp-HANDOFF-deep-inode-wedge-is-last-blocker]] [[sess111_reframe_bnobt_red_herring]].

---
name: sess45-next-blocker-dabuf-map-hole-dir-extent-xfs_create-shutdown
description: sess45: after the crash_consistency inode-cluster fix (KEEP), full ./run.sh 2 tcp = 0/17 because an EARLY test wedges test1: xfs_create→xfs_dabuf_map…
metadata:
  type: project
---

## sess45 (ccloop 8ddb16a2, build EF006296) — full-suite status after the inode-cluster fix

### The inode-cluster crash_consistency wedge is FIXED + VERIFIED standalone
([[sess45-FIX-partial-iwrite-skips-fresh-free-inodes-INODE_ALLOC_BUF]], build C0554679/EF006296,
KEEP). `./run.sh 2 tcp dlm_fairness crash_consistency` → both PASS 2/2, BADVERIFY=0, shutdown=0.

### BUT full `./run.sh 2 tcp` (17 tests) = 0 PASS / 17 FAIL — NEW early wedge cascades.
test1 shut down; test2 stayed healthy (WRITE_OK). The all-fail incl. trivial precond_readiness
(4/7 write checks failed = EIO after shutdown) is the cascade: run_coord needs BOTH nodes PASS, so
once test1's FS is down every test fails. test1 was already up ~240s when the suite started, so the
uptime-300.9s shutdown was actually EARLY in the suite (precond_readiness/cache_coherency).

### ROOT of the new shutdown (test1 dmesg, decisive):
```
[300.898] XFS Internal error !(flags & XFS_DABUF_MAP_HOLE_OK) at line 2814 of xfs_da_btree.c.
          Caller xfs_dabuf_map.constprop.0
[300.903] XFS Internal error xfs_trans_cancel at line 1060 of xfs_trans.c. Caller xfs_create
[300.905] XFS Corruption of in-memory data (0x8) at xfs_trans_cancel:1061. Shutting down filesystem.
```
=> a CREATE (xfs_create, adding an entry to a directory) maps a directory block via xfs_dabuf_map
and bmapi returns a HOLE where a dir block must exist — the directory's (in-core) extent map
references a block that isn't mapped. HOLE not allowed there → xfs_corruption_error → the create's
dirty transaction is cancelled → SHUTDOWN_CORRUPT_INCORE. This is the dir-coherency M2 family
(STALE in-core dir extent map / block0 daddr divergence across the reuse — see
[[sess-tcp-WHY-merge-misses-it-EX-held-stale-incarnation-fork]], [[sess33-PROVEN-ROOT-inode-data-block-double-alloc]]).
NOT the inode-cluster wedge (P45-INIT/P45-WR-CLUSTER/P-ICLUSTER-BADVERIFY all 0× this run).
force_block=0 kept (sess44). likely the shared ROOT dir /mnt/shared whose extent map is stale right
after mount, so the first cross-node create hits the hole.

### NEXT (RULE 4): reproduce standalone — `./run.sh 2 tcp cache_coherency` (the historically-hard
dir-coherency test) on a fresh prep; confirm the DABUF_MAP_HOLE fires. Then instrument xfs_dabuf_map
/ xfs_da_read_buf (xfs_da_btree.c ~2814) to dump the dir ino, the requested bno/mapped fsb, the
in-core if_nextents vs on-disk, and whether this is a stale prior-incarnation extent map (di_gen
mismatch) or a genuinely-lost dir block. Likely fix locus = the dir-inode reload on EX acquire
adopting the peer's fresh incarnation / the dir-data durability + extent-map coherency
(mxfs_dir_data_durable / b_mxfs_dir_gen invalidation). [[sess45-FIX-partial-iwrite-skips-fresh-free-inodes-INODE_ALLOC_BUF]]</body>

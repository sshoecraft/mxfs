---
name: caw-sess4-inode-readstorm-code-map-drain-only-flushes-dirty
description: sess4 code-map for the 32-node inode-cluster read storm. RULED OUT: dir-block reads (P-DSCAN=6), drain_inode_buffers (flushes dirty only), icache re-…
metadata:
  type: project
---

## 32-node inode-cluster read-storm — code map + RULED-OUT list (sess4)

Storm = cold re-reads of AG0 fsblk~18300-18700 (inode cluster holding root ino128 + .dlm_scaling
+ reused-dir/subdir inodes) at 32-node load (~31000-41000 reads/3-4s; ROOT memo: "cold cache
MISSES inc_rc=-ENOENT, NOT invalidations" -> buffers are genuinely EVICTED then re-read).

### Read path (where the cold read lands)
`xfs_imap_to_bp` (xfs/libxfs/xfs_inode_buf.c:318) -> xfs_trans_read_buf(ddev, imap->im_blkno).
A miss here = one cold LUN read. (A miss-counter probe here is RISKY: xfs_buf_incore holds/locks
buffers in a hot path. Prefer ftrace tests/trace_reads.sh + eviction-site tags.)

### RULED OUT as the storm cause (sess4, by code read + probe)
1. **dir-DATA-block reads** (xfs_da_read_buf): P-DSCAN probe fired only 6x in a live dlm_scaling@32
   run. NOT the storm. `dir_shared_pr_skip` param is therefore inert/misdirected.
2. **mxfs_dlm_ag_drain_inode_buffers** (xfs_mxfs_dlm.c:23368, called :25689 on AG-BAST): only
   FLUSHES inode bufs WITH pending log items (dirty); does NOT evict CLEAN buffers. Not the evictor.
3. **icache inode-cluster re-stale** (xfs/xfs_icache.c:1371-1440, gated mxfs_inode_cluster_owned_skip
   =1 default): the perf skip at :1409 ENGAGES for allocated inodes (dinode_cached_allocated==true).
   The shared inodes are always allocated -> skip engages -> NO re-stale here. Not the storm. (This
   path re-staled ~32x/cluster before sess19's skip; the skip already fixed that.)
4. **LRU / inode_cache_max**: the HOT shared set is TINY (~34 inodes: root + .dlm_scaling + 32
   subdirs). LRU keeps hot buffers; a tiny hot set can't be cache-size-evicted. inode_cache_max /
   cache_mem_pct levers won't help. NOT LRU.

### OPEN (the actual evictor) — needs the eviction-provenance probe
The hot shared inode-cluster buffers are FORCE-evicted by an mxfs path (NOT LRU, NOT re-stale).
Candidates (Fable): AG-BAST collateral drain of CLEAN inode bufs; noino BAST path
(mxfs_dlm_noino_bast_work_fn); MHT idle-demote; a coherency xfs_buf_stale. NEXT: grep every
xfs_buf_stale / xfs_buf_delwri on an xfs_inode_buf_ops buffer reachable from the AG-BAST /
noino-BAST / release paths; add a reason tag {BAST_EX,BAST_PR,MHT,NOINO,LRU,SELF} at each; run
dlm_scaling@32 (dirwr) and read which reason dominates for daddr in AG0. THEN scope the fix: do
NOT evict a clean inode-cluster buffer whose inode(s) are held >=PR (DLM lock => no peer modified;
GFS2 glock principle). Existing params to study: inode_mht_ms=300 (EX-hold batching),
inode_cluster_owned_skip=1, fua_skip_owned_inode (UNSAFE AG-based). One fix unblocks dlm_scaling@32
+ cache_coherency@32 + crash_consistency@32 + dir_reuse@16/32.
See [[AAA-sess4-HANDOFF-caw-criteria-unified-readstorm-root]].
</body>

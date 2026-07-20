---
name: sess47-FIXED-two-8tcp-wedges-relsafe-lock-and-ilockend-defer
description: sess47(ccloop): FIXED 2 of the 8/tcp dir_reuse WEDGES (build E9D1B1CB). Test now COMPLETES (no timeout). Remaining blocker = reused-dir DABUF_MAP_HOL…
metadata:
  type: project
---

## sess47 (ccloop 4cb2d0a2) — two 8/tcp MASS-wedge ROOTS fixed (RULE 4, NFS-stream proven)

Build **E9D1B1CB** = B349FD6E + two liveness fixes. Diagnosis method: enabled
`DRC_STREAM=1` (live `dmesg --follow` per node → NFS, survives node death) in
`tests/drc_detail8.sh`; ran reboot+test in foreground; harvested hung-task
stacks from `/src/mxfs/tests/tcp/drc_cap/stream_rank*.log`.

### FIX 1 — lock-free extent walk in release flush (xfs_mxfs_dlm.c ~8676)
bast_process called the NON-relsafe `mxfs_dir_flush_data_blocks(ip)` which walks
`for_each_xfs_iext(&ip->i_df)` **WITHOUT ip->i_lock**. On a REUSED dir a concurrent
extent-fork mutation corrupted the lock-free walk → GARBAGE br_startblock → garbage
out-of-range daddr (captured: daddr 0x1e0d648fc6f390, EOFS 0x63cffb0, varying each
iter). flush_one_daddr's blocking get tripped `xfs_buf_map_verify` WARN_ON(1) at
pal/linux/xfs_buf.c:423 **410727×** → synchronous console printk flood burns CPU →
node stops servicing TCP >25s → TCP_USER_TIMEOUT → declared dead → round work lost
(the DOMINANT sess46 MASS loss). FIX: `if (mxfs_drain_ilock_read(ip)) mxfs_dir_flush_data_blocks_relsafe(ip);`
— relsafe snapshots daddrs under i_lock(read), DROPS i_lock, then does the gets
(ABBA-safe). Result: warn423 0, rank2 stream 773MB→3.6MB.

### FIX 2 — inline bast flush self-deadlock from ilock_end (xfs_mxfs_dlm.c ~15280)
`mxfs_dlm_ilock_end` ran `mxfs_dlm_bast_process` INLINE from xfs_iunlock. A readdir
(xfs_dir2_leaf_getdents) still HOLDS a dir DATA buffer at the iunlock point →
flush_one_daddr's blocking xfs_buf_lock self-deadlocks on the buffer the caller
holds (captured: `ls` + mxfs-ino-bast kworker both D-state in
flush_one_daddr→xfs_buf_lock). Latent before — masked by FIX-1's garbage walk
failing fast; exposed once the walk became ILOCK-correct. FIX: replace the inline
path with `ihold(VFS_I(ip)); if(!queue_work(m_mxfs_inode_bast_wq,&ip->i_dlm_bast_work)) xfs_irele(ip);`
— defer to the bast workqueue (clean kworker, no held buffers; sets demoter=kworker;
state already DEMOTING blocks re-acquire). Both fixes KEEP.

### RESULT: test now COMPLETES (~320s, no timeout) instead of wedging. But FAIL 0/8.

### REMAINING BLOCKER = reused-dir DABUF_MAP_HOLE shutdown (sess20 family)
test5 shut down in xfs_create on reused dir ino=131: `!(flags & XFS_DABUF_MAP_HOLE_OK)`
at xfs_da_btree.c:2876, req_bno=8388609 (2nd leafn). P15-EXTSHAPE: extent map has
off=3, off=8388608(leaf,1blk), off=16777216(free,1blk) — but NOT 8388609. A da-node
references leafn 8388609 that isn't in this node's extent map = partial reused-dir
coherency (da-node fresh, extent map stale). ONE node shutdown → 0/8.

### dir_postread_reread=1 (sess20 stale-leaf heal): ELIMINATES the DABUF_HOLE
shutdown (0 shutdowns) BUT introduces a SLOWNESS wedge — holder keeps dir VFS
i_rwsem(write) doing slow leaf/node re-reads, openers (md5sum/bash) block >18s in
open_last_lookups→down_read → timeout (RULE 0 fail). NOT viable. Need a non-slow fix.

### NEXT (RULE 4): make the DABUF_MAP_HOLE site RELOAD the dir extent map (multinode,
reused dir) and retry, instead of force_shutdown — a transient stale map mapping to a
hole is coherency staleness, not on-disk corruption. If hole persists post-reload →
real corruption. See [[sess46-REFRAME-8tcp-dominant-failure-is-node-isolation-wedge-not-doublegrow]] [[sess20-PROVEN-dabuf-hole-is-stale-leaf-fixed-by-postread-leaf-only]].
</body>

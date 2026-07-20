---
name: sess28-ROOTFIX-inode-revert-fresh-gen-on-create-reuse
description: sess28 ROOT FIX (build C887AFA3): dir_reuse 2/tcp inode-revert (P26-IGET-FAIL) FIXED. Root=cache-HIT create reuse preserved stale in-core gen behind…
metadata:
  type: project
---

## sess28 (ccloop 8ddb16a2) — ROOT FIX for dir_reuse_coherency 2/tcp inode-revert

### PROVEN ROOT (decisive, RULE 4) of P26-IGET-FAIL (the 27-session primary blocker)
node2 creates node2_f10=inode 2099081 with `incore_gen=919987021`, but DISK shows 2099081 freed at `disk_gen=919987022` (one HIGHER). The `P25-RESURRECT-SKIP` guard in xfs_iflush (xfs/xfs_inode.c ~4619) sees `disk_gen > incore_gen` (the "peer freed this ahead of us" pattern) and SKIPS node2's flush of its OWN just-created file → mode=alloc never reaches the platter → reader's dirent→iget(2099081) returns a FREE inode → P26-IGET-FAIL → lookup_fail.

WHY incore_gen was stale (= disk-1): XFS assigns a fresh random gen to a new inode ONLY on the **cache-MISS** create path (xfs/xfs_icache.c ~1171, `xfs_has_v3inodes && XFS_IGET_CREATE → i_generation = get_random_u32()`). The **cache-HIT/recycle** path PRESERVES the in-core gen (xfs_reinit_inode line 356). Under MXFS multi-node a freed inode LINGERS in cache (held EX, Invariant 2, never reclaimed — peer inode ALLOCATION via AGI/inobt does NOT BAST the per-inode lock), so re-allocating the same inum cache-HITs the stale struct. A peer (node1 rm-rf) freed the prior incarnation on disk, bumping di_gen (XFS bumps gen by 1 on free, xfs_inode_util.c ~866), which our idle cache never saw → stale in-core gen stuck 1 behind disk → RESURRECT-SKIP every round. Single-node never hits this (freed inode is reclaimed → always cache-miss → fresh gen).

Decisive evidence: P28-CREATE (creator-side, name→inum→gen probe I added) showed node2_f10 stuck at gen=919987021 across rounds; P25-RESURRECT-SKIP `incore_gen=919987021 disk_gen=919987022 comm=xfsaild`; created inum MATCHED the IGET-FAIL inum (so NOT dirent staleness — genuine inode revert).

### THE FIX (build C887AFA3, KEEP)
xfs/xfs_inode.c `xfs_icreate()`, right after `xfs_inode_init(tp, args, ip)`:
```c
if (xfs_has_v3inodes(mp)) {
    VFS_I(ip)->i_generation = get_random_u32();
    xfs_trans_log_inode(tp, ip, XFS_ILOG_CORE);
}
```
This is the cache-HIT analogue of the cache-MISS randomize: every newly-allocated inode gets a fresh gen regardless of cache state, so its gen is independent of the stale freed predecessor and the flush is never mistaken for a stale resurrection. RESULT: RESURRECT-SKIP count 0 (was firing every round), P26-IGET-FAIL GONE, lookup_fail=0.

### REMAINING (next): readdir=184/200 dir-DATA-block lost-update
With inode-revert fixed, dir_reuse now fails at ~round 12 with `readdir=184/200 lookup_fail=0` — 16 dirents DURABLY LOST from the shared dir's data blocks (ndb=2). This is the dir-BLOCK (xfs_dir3_data_buf_ops) analogue: two nodes concurrently add 100 dirents each; a stale cached dir block write reverts ~16 of the peer's committed dirents. NOT inode-cluster (my sess28 inode-write skip doesn't cover dir blocks). Existing machinery: mxfs_buf_xfsaild_skip_dir_write (sess17, default on), mxfs_dlm_dir_durable_signal, read-time i_dlm_dir_gen invalidation — insufficient. See [[sess28-write-side-skip-and-instrumentation]].

### Also landed this session (write-side defensive, KEEP — complements but did NOT fix alone)
mxfs_submit_partial_inode_write (pal/linux/xfs_buf.c): write only owned(in-core mode!=NL) | logged(b_li_list) | bli_dirty(BLI di_next_unlinked ranges); OMIT free(di_mode==0)/NL-not-logged co-resident slots; removed BLI_DIRTY bail (now partial-writes BLI-dirty clusters, force-writing BLI ranges). New module param `iwr` (xfs_mxfs_dlm.c) gates P28-IWR/P28-IWR-FREEWR/P28-CREATE decision probes. GPT-5.5 (RULE 5) endorsed "never write unowned/unlogged slots" + fix per-inode grant lifecycle.
</body>
</invoke>

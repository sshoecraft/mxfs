---
name: sess17-merge-impl-approach-and-txn-blocker
description: sess17 impl analysis for the dir-block union-merge fix: use xfs_dir_lookup+xfs_dir_createname per peer dirent; BLOCKER = needs own txn (injecting int…
metadata:
  type: project
---

## sess17 IMPLEMENTATION ANALYSIS for the block-level dirent union-merge fix [[sess17-FIX-PLAN-blocklevel-dirent-merge]].

## CONCRETE APPROACH (reuses existing dir machinery — much simpler than manual bestfree/leaf mgmt):
`mxfs_dir_block_merge_peer(struct xfs_trans *tp, struct xfs_inode *dp)`:
1. Gate: param (default off), multinode, S_ISDIR, fmt EXTENTS/BTREE (shortform → existing sf_merge), extents loaded, bt_bdev present.
2. kmalloc geo->blksize buffer. for_each_xfs_iext over dp->i_df; for each dir-block-sized chunk daddr d: plain-read disk block (lba = d + bt_sector_offset, mxfs_pal_bdev_read_plain_bdev under fua_disable=1) into rb (a STABLE snapshot — modifying the live dir won't disturb it).
3. Identify DATA blocks by MAGIC: rb[0..3]=='X','D',('D'|'B'),'3' (XDD3 data / XDB3 block); verify ((xfs_dir3_blk_hdr*)rb)->owner == dp->i_ino. Skip leaf(XDL3)/free(XDF3)/node.
4. Walk dirents from geo->data_entry_offset (end = XDB3 ? (char*)xfs_dir2_block_tail_p(geo,hdr)-rb : blksize), skipping xfs_dir2_data_unused (freetag==XFS_DIR2_DATA_FREE_TAG, advance by length). For each xfs_dir2_data_entry dep: name={dep->name, dep->namelen, xfs_dir2_data_get_ftype(mp,dep)}, inum=be64_to_cpu(dep->inumber). Skip "."/"..".
5. rc = xfs_dir_lookup(tp, dp, &name, &cur, NULL, NULL); if rc==-ENOENT → this peer dirent is missing from our in-core dir → xfs_dir_createname(tp, dp, &name, inum, 0) to re-add it. (lookup reads the live/stale in-core dir; createname adds to it.)
- APIs confirmed: xfs_dir_createname(tp,dp,const xfs_name*,xfs_ino_t inum,xfs_extlen_t total); xfs_dir_lookup(tp,dp,const xfs_name*,xfs_ino_t*,xfs_name* ci,uint8_t* ftype). Both expect dp ILOCK_EXCL held (true on modify path).
- HOOK POINT: xfs_inode.c create path line ~1365 (after mxfs_dlm_dir_modify_refresh(dp); dp ILOCK_EXCL @1353 + tp active). Also remove ~3495, rename ~3908.

## THE BLOCKER (why a one-shot is unsafe): xfs_dir_createname must run in a transaction. Injecting the merge's createname calls into the OUTER create/remove/rename transaction `tp` is dangerous: if a createname fails mid-merge (e.g. ENOSPC — tp was reserved for ONE op, not N extra adds), it can leave `tp` DIRTY, and the subsequent xfs_trans_cancel on a dirty trans = "Corruption of in-memory data" FS SHUTDOWN (same failure class the sess82 re-validate guard at xfs_inode.c ~3470 was added to avoid). So the merge needs its OWN transaction (alloc+commit) BEFORE the operation's transaction, OR a reservation big enough + rollback-safe handling.

## RECOMMENDED NEXT IMPL: do the merge in a SEPARATE transaction at the PRE-LOCK hook (mxfs_dlm_dir_modify_reload_prelock, xfs_inode.c ~1296/3448/3817 — runs with NO outer tp, NO ILOCK held). There: alloc a dedicated trans (xfs_trans_alloc with tr_create or tr_dir reservation sized for the expected missing count), ilock dp EXCL, run the lookup+createname merge, xfs_trans_commit (or cancel cleanly on error — clean since self-contained), iunlock. Then the normal operation proceeds on a now-merged in-core dir. This isolates merge failures from the operation's transaction. Verify against tests/cc_blockdir_probe.sh (dirwr=1), then full ./run.sh 2 tcp 16/16 x3, watching cache_coherency/zero_silent_loss/rename for regressions.

## RISKS to watch: (1) perf — reading all data blocks per modify is costly (RULE 0); trigger only when a block is undestaged AND peer advanced gen, or rate-limit. (2) createname re-adding an entry the peer LATER removed would resurrect it — but crash_consistency is create-only so safe; for general correctness, gate the merge to additive workloads or compare gens. (3) reservation sizing. Build 6D51CDDF has the P17 detector to validate the merge closes the clobber. [[sess17-CONFIRMED-staleflush-clobber-P17]]

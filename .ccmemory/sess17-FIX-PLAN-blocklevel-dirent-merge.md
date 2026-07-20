---
name: sess17-FIX-PLAN-blocklevel-dirent-merge
description: sess17 FIX PLAN for 2/tcp crash_consistency: block-level dirent union-merge at acquire is UNAVOIDABLE (all simpler fixes ruled out with evidence).
metadata:
  type: project
---

## sess17 FIX PLAN (next iteration) for 2/tcp crash_consistency, building on CONFIRMED root [[sess17-CONFIRMED-staleflush-clobber-P17]].

## THE PROXIMATE MECHANISM (proven): a node re-acquires dir-EX with cached dir data block 496 that is UNDESTAGED (its own un-written logged mods) AND missing the peer's committed entries. The acquire keep-guard (mxfs_dir_evict_data_blocks ~2043: skip evict when `in_ail && !incarn_aba && undestaged`) SKIPS it → never cold-reads the peer's image → never adopts peer entries. The node then durably FLUSHES that stale base (release-drain kworker via mxfs_dir_flush_data_blocks, OR xfsaild) → peer's dirents durably lost (P17-CLOBBER-DROP fired BOTH vectors: comm=kworker on test1, comm=xfsaild on test2).

## ALL SIMPLER FIXES RULED OUT WITH EVIDENCE THIS SESSION (do NOT re-explore):
- **Gen-propagation gap / local-gen gating**: NOT it. `mxfs_dir_force_evict=1` is already DEFAULT-ON (xfs_mxfs_dlm.c ~1931) — evict runs UNCONDITIONALLY every cross-node modify regardless of i_dlm_dir_gen. 496 is still skipped because undestaged, not because of the gen.
- **wseq-tracking artifact** (block actually written but wseq=0 wrongly): NOT it. In the probe daddr 496 is freed+reused each iter; a fresh dir's 496 legitimately has lseq>0,wseq=0 (real logged-but-UNWRITTEN node1 entries) — genuinely undestaged. The keep-guard is CORRECTLY protecting real un-written local work.
- **Cold-read on acquire (evict the undestaged block)**: would DISCARD this node's own un-written entries → loses local work.
- **force-evict-on-release**: TRIED+REFUTED sess96 (resurrected stale entries; code comment ~3956).
- **xfsaild/release chokepoint-SKIP**: REFUTED this session — would_skip fired 0× in real suite; tenure-mismatch arm corrupts on tenure=0 fresh blocks. [[sess17-detector-refutes-enforce-and-cc-flaky-pass]]
=> Because the block legitimately holds BOTH this-node un-written entries AND must adopt the peer's durable entries, neither keep nor cold-overwrite is correct. **A block-level dirent UNION-MERGE is UNAVOIDABLE.**

## THE FIX = BLOCK-LEVEL DIRENT UNION-MERGE (data-block analogue of sess14 shortform mxfs_dir_sf_3way_merge): when a dir DATA block is undestaged AND a peer modified the dir, read the peer's DURABLE block from disk (plain read OK under fua_disable=1) and, for every dirent present on disk but ABSENT in-core, ADD it to the in-core block; keep our own un-written entries → union, no loss either way. Entries are name-disjoint across nodes (node1_* vs node2_*) so no conflict.
- Needs ILOCK_EXCL + an active transaction to log the adds + free-space (bestfree) mgmt + leaf/leafn hash-index update + dir nextents. Reuse libxfs/xfs_dir2_data.c: xfs_dir2_data_make_free / xfs_dir2_data_use_free / xfs_dir2_data_log_entry, and xfs_dir2_leaf/leafn add-hash. Do it on the MODIFY path (xfs_create/etc, which hold ILOCK_EXCL) inside their trans, replacing the keep-guard skip with a merge for the undestaged+peer-advanced case. Bounded scope (only fires undestaged+peer-modified).
- WHERE: mxfs_dir_evict_data_blocks runs with no trans (ILOCK_SHARED in consumer_refresh). The merge can't go there. Better: a new mxfs_dir_block_merge(dp) called from the dir-MODIFY paths after they have a transaction, iterating undestaged dir blocks, merging in peer dirents read from disk. Or integrate into xfs_dir2 lookup-of-free path.

## ALSO INVESTIGATE: release-drain COVERAGE — P-RELFLUSH fired only ONCE per node (block 496) though the lost entry (node2_f17.md5) lived in the md5 block ~14652648. Confirm mxfs_dir_flush_data_blocks (~1184) flushes EVERY modified dir block at release; a block already xfsaild-written STALE (clean → !needs_flush at release) is a second loss path the fence won't fix.

## TOOLING (build 6D51CDDF, dirwr=1 dirskip=0): P17-CLOBBER-DROP (pal/linux/xfs_buf.c per-daddr count-decrease — CAVEAT key=(daddr,owner) not i_generation; harden w/ incarnation), P16-DIRBLK-SUBMIT, P-EVICT-SKIP/DONE, P-RELFLUSH, P35E names. Reproducer tests/cc_blockdir_probe.sh (fails iter ~5-14 w/ dirwr=1). `./run.sh 2 tcp`=15/16. Marker NOT written. [[sess17-HEAD-shared-dirblock-staleflush-wseq0]]

---
name: sess21-leaf-rebuild-fix-works-90of91-residual-stale-datablock
description: sess21 leaf-rebuild fix (build 71E1C8A9) WORKS 90/91 on dir_reuse_coherency; residual 1-entry miss = stale in-core data block at rebuild. Union fix n…
metadata:
  type: project
---

## sess21 (ccloop 8ddb16a2) — leaf-rebuild fix VALIDATED (mostly). Build 71E1C8A9.

## THE FIX (implemented, KEEP — see [[sess21-PROVEN-root-pinned-leaf-staleRMW-and-gpt-rebuild-fix]]):
- New inode flag MXFS_IF_DIR_LEAF_STALE (xfs/xfs_inode.h 1<<21). Set in BOTH evict-skip-leaf sites (mxfs_dir_evict_data_blocks ~2094 + mxfs_dir_drain_evict_data_blocks ~3322 else) when a LEAF block is skipped (pinned/undestaged) — i.e. exactly the proven stale-leaf-keep.
- New fn mxfs_dir_rebuild_leaf_from_data(args) in xfs/libxfs/xfs_dir2_leaf.c (declared xfs_dir2_priv.h, #ifdef __KERNEL__): scans the dir DATA blocks (db 0..ltp->bestcount-1), collects {hashval=xfs_dir2_hashname, address=xfs_dir2_db_off_to_dataptr} per live dirent, sorts by (hash,addr) via a u64 ((hash<<32)|addr) + sort(), OVERWRITES the (possibly pinned) leaf ents+hdr+bests and RELOGS via xfs_dir3_leaf_log_header/ents/bests (NO XBF_DONE clear, NO extra DLM acquire). Bails cleanly (return 0, no mutation) on block/node format, holes, would-overflow-leaf, OOM.
- Called at top of xfs_dir_createname (xfs/libxfs/xfs_dir2.c ~533, #ifdef __KERNEL__) gated on xfs_iflags_test_and_clear(dp, MXFS_IF_DIR_LEAF_STALE) — fires ONCE per acquire (first create clears flag; FASTEX creates in same tenure reuse the now-correct leaf). Perf-safe.

## RESULT (dir_reuse_coherency 2/tcp DRC_ROUNDS=15, NO dirwr): checks=91 passed=90 FAILED=1. Rounds 1-14 PASS; round 15 lookup_fail=1 (node2_f34.md5 only). NO shutdown either node. (Was: lookup_fail 2-9 growing to 22-29 + round-17 shutdown.) Reservation OK (no overrun/shutdown). P21S still fires (120/132) — leaf still skipped, rebuild fixes it after.

## RESIDUAL ROOT (1 miss): the rebuild read an IN-CORE data block that was itself STALE (undestaged-skipped at acquire by drain_evict, so missing the peer's recent add to THAT block). readdir(cold)=200 proves the entry IS durable on disk; the rebuild's cached read missed it. = GPT's MXFS_DIR_DATA_UNSAFE edge.

## NEXT FIX (union read): in mxfs_dir_rebuild_leaf_from_data, rebuild from the UNION of (a) the in-core data block (has this node's uncommitted adds; hook-refreshed if clean) and (b) a COHERENT plain-bio read of the SAME physical daddr (dbp->b_maps[0].bm_bn + bt_sector_offset, len=BBTOB(dbp->b_length), mxfs_pal_bdev_read_plain_bdev — fua_disable=1 so plain bio = coherence point; has peer's durable adds). Collect {hash,addr} from BOTH, sort, DEDUP consecutive equal (same entry from both sources), write unique. Size kv array 2*max_ents. Disjoint names => union by (hash,addr) is exactly complete. The rebuild fires right after acquire (before this tenure's adds) so disk has all released work incl this node's prior; union with in-core covers any in-flight. Validate disk block magic (XFS_DIR2/3_DATA_MAGIC) + owner==dp->i_ino before parsing; if disk read/magic bad, fall back to in-core only for that block.

## Harness fixes this session (KEEP): run.sh per-node srcversion assert (catches stale-build deploy); prep_node.sh umount -f + rmmod retries; MXFS_TEST_ENV passthrough; tests/force_reset.sh. Repro: MXFS_TEST_ENV="DRC_ROUNDS=15" ./run.sh 2 tcp dir_reuse_coherency (caps before the round-17 shutdown wedge → fast cycles). Full criterion = DRC_ROUNDS=24 (default) must pass + full ./run.sh 2 tcp suite 100%.

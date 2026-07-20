---
name: sess27-FINAL-bug2-is-lookup-bug-datascan-misses-present-dirent
description: sess27 FINAL/last-mile: under partial_iwrite=0, node2_f10 dirent is DURABLY in the data block (readdir finds it, 2x drop_caches) + inode valid, but d…
metadata:
  type: project
---

## sess27 (ccloop 8ddb16a2) — LAST-MILE finding for dir_reuse_coherency 2/tcp

### Under partial_iwrite=0 (whole inode writes), the remaining failure is a LOOKUP bug, NOT durability
Build 9753480F, 2-node TCP, LIO. After a failing run, on test1 (dir left mounted):
- `ls .dir_reuse_coherency | grep node2_f10` → PRESENT. Survives TWO `echo 3 > drop_caches` (fresh disk reads) → the data block DURABLY contains node2_f10's dirent.
- `stat node2_f10` → ENOENT. P26-IGET-FAIL=0 (inode NOT reverted — whole writes fixed BUG1). P26-LKERR + P26-DSCAN-MISS fire → the leaf lookup misses AND the datascan fallback misses.
- So: the dirent IS present in the data block (readdir reads it) and the inode IS allocated, but BOTH the leaf-hash lookup AND mxfs_dir2_datascan_lookup FAIL to find a dirent that is physically present. **This is a read/lookup-path bug, not a write-side durable lost-update.** ndb=2 (correct; di_size=8192 not stale — the extent-map ndb fix changed nothing).

### Implication: partial_iwrite=0 + a datascan/lookup fix may PASS dir_reuse (and the suite)
partial_iwrite=0 already: fixes BUG1 inode-revert, keeps data blocks durable, and PASSES cache_coherency/strong_consistency/posix_multi ([[sess27-partial-iwrite-0-viable-only-leafhole-remains]]). If the datascan is fixed to find the present dirent, lookup_fail→0 and dir_reuse should PASS. THE LAST MILE.

### NEXT (debug why datascan misses a PRESENT dirent) — xfs/libxfs/xfs_dir2_leaf.c mxfs_dir2_datascan_lookup
PRIME SUSPECT: `args->cmpresult` interaction. The scan does `if (cmp != XFS_CMP_DIFFERENT && cmp != args->cmpresult) {...}` then for XFS_CMP_EXACT returns the hit. But `args->cmpresult` may already be set to XFS_CMP_EXACT by the FAILED leaf lookup (xfs_dir2_leaf_lookup_int sets args->cmpresult on a case path before returning -ENOENT), making `cmp != args->cmpresult` FALSE for an exact match → the present dirent is SKIPPED. FIX CANDIDATE: reset `args->cmpresult = XFS_CMP_DIFFERENT` at the top of mxfs_dir2_datascan_lookup before scanning. Also verify: scan bounds (data_entry_offset..xfs_dir3_data_end_offset), that node2_f10 is actually in block 0 or 1 (add a probe logging every dirent name the datascan sees in each block for the target name), and that xfs_dir3_data_read returns the SAME buffer/content readdir sees.
DECISIVE PROBE: in the datascan inner while-loop, when args->name matches "node2_f10", log "P-DSCAN-SEES name=X cmp=%d cmpresult=%d db=%d" so you see whether it SEES node2_f10 but skips it (cmpresult bug) vs never sees it (wrong block / read).

### Then: confirm full ./run.sh 2 tcp passes with partial_iwrite=0 + the lookup fix (×3 = 100%). Decide whether to flip mxfs_partial_iwrite default to 0 or make partial-write whole-write-when-no-peer-shares-cluster. FUA is DEAD (LIO) — never chase it. See [[sess27-PROVEN-root-durable-inode-alloc-revert-not-leafhole-not-fua]], [[sess27-gpt-design-release-drain-is-foundation-unified-root]]. Tree 9753480F clean; reboot cluster before runs (test2 boot-wedge).
</body>

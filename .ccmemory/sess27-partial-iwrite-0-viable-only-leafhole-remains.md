---
name: sess27-partial-iwrite-0-viable-only-leafhole-remains
description: sess27 LEAD: partial_iwrite=0 (whole inode writes) PASSES cache_coherency+strong_consistency+posix_multi (no false-sharing regression) AND fixes dir_…
metadata:
  type: project
---

## sess27 (ccloop 8ddb16a2) — STRONG LEAD for the next session

### partial_iwrite=0 (whole-buffer inode writes) is a VIABLE direction
Build 2C3150CB, 2-node TCP, LIO target. `MXFS_EXTRA_MODARGS="partial_iwrite=0"`:
- `cache_coherency` PASS 2/2, `strong_consistency` PASS 2/2, `posix_multi` PASS 2/2 — the inode-coherency / false-sharing tests do NOT regress with whole-buffer inode writes. (The sess115 partial-inode-write was added for "cross_write_read xfs_inode_buf_verify corruption"; current AG-affinity apparently keeps inode clusters single-owner so whole writes are safe in practice.)
- `dir_reuse_coherency` with partial_iwrite=0: BUG1 inode-alloc-revert (P26-IGET-FAIL) is GONE; only BUG2 (durable dir LEAF-hash hole: P26-LKERR + P26-DSCAN misses, P22-DATASCAN-HIT=0) remains.

### Implication / proposed path for next session
1. **Adopt whole inode writes** (either flip `mxfs_partial_iwrite` default to 0, or — cleaner — make `mxfs_submit_partial_inode_write` whole-write when the cluster has no peer-held inode; but the 3 passing tests suggest plain default-0 is acceptable). FIRST verify the FULL `./run.sh 2 tcp` suite passes with partial_iwrite=0 EXCEPT dir_reuse (confirm no other regression — esp. anything inode-cluster-sharing).
2. **Then fix BUG2 (dir LEAF-hash hole)** — the only remaining dir_reuse failure under whole-writes. Under partial_iwrite=0, lookups miss in the leaf and the datascan fallback (mxfs_dir2_datascan_lookup in xfs/libxfs/xfs_dir2_leaf.c) RUNS (P26-DSCAN fires) but MISSES (P22-DATASCAN-HIT=0). readdir LISTS the names (data blocks have them) but datascan under-scans: it uses `ndb = dp->i_disk_size / geo->blksize` — likely STALE/small di_size at lookup time vs the extent map readdir uses. FIX CANDIDATE: make the datascan walk the data-fork EXTENT MAP (like xfs_dir2_leaf_getdents) instead of ndb-from-di_size, so it scans every data block readdir can see → heals the leaf-hash hole at read time. (Read-side heal is valid here because the DATA blocks ARE coherent — readdir proves it. The leaf is just a stale hash index.) Verify the name IS in the data blocks the datascan reads; if the datascan finds it, lookup_fail→0.
3. If BUG2 is NOT datascan-healable (data block also stale), it's a durable leaf lost-update → write-side per [[sess27-gpt-design-release-drain-is-foundation-unified-root]] (ensure leaf fully destaged + not in-AIL at peer re-acquire; P21S-EVICTSKIP-LEAF in_ail=1 was the acquire-skip symptom).
4. Full `./run.sh 2 tcp` ×3 = 100% for the criterion.

### Reminders
- Tree is CLEAN at 2C3150CB (diagnostics + partial_iwrite toggle default 1 + unused b_mxfs_idirty_mask). FUA is DEAD (LIO) — never chase fua_disable=0. Reboot cluster (tests/reboot_cluster.sh 2) before runs — test2 auto-mounts+wedges on boot; run.sh prep handles it post-reboot.
- See [[sess27-PROVEN-root-durable-inode-alloc-revert-not-leafhole-not-fua]], [[sess27-refuted-persistent-idirty-mask-and-next-steps]].
</body>

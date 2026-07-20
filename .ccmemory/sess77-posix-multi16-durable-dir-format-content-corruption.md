---
name: sess77-posix-multi16-durable-dir-format-content-corruption
description: sess77: posix_multi16 >600s ROOT = DURABLE dir-inode format/content corruption (di_format=EXTENTS but literal area holds shortform dirents) under 16-…
metadata:
  type: project
---

## sess77 (run 14d31183) — posix_semantics_multi16 >600s ROOT (clean cluster, build 3DC74E7D)

### Chain of causation (PROVEN on a freshly-REBOOTED clean 16-node cluster)
1. posix_multi16 wraps run_tests.sh --phase all. Single phase = ~11s (fast). All cost is the
   14-test CLUSTER phase. Each cluster test uses tests/lib/cluster.sh barriers (barrier_signal =
   `touch .mxfs_barriers/<name>/nodeN`; barrier_wait polls `find` til N signals, 120s timeout).
2. Under the 16-node concurrent same-dir create storm, ONE random node's mxfs mount FORCE-SHUTS-DOWN
   (only 1 of 16 nodes; this run = test11). After shutdown every op on that node returns EIO →
   its barrier_signal touch fails (rc=1) and its barrier_wait sees 0/16 → 120s timeout. Multiple
   tests × 120s timeouts cumulate > 600s → criterion FAIL "elapsed>600s". NOT a single hang.
3. Earlier "lost dirent at 16 nodes" leads were CONTAMINATION: an orphaned run_tests.sh from a
   pkill'd run left D-state procs holding AGI buffer locks (memory sess52). On a CLEAN reboot,
   repro_barrier_coherency 16-node PASSES in 6s and test_concurrent_mkdir alone PASSES. MUST full
   `virsh destroy+start` ALL nodes (not just reset4.sh rmmod) before trusting any 16-node result.

### The shutdown root (node11, durable on-disk corruption)
- dir inode 0x1c001b2 = 29360562 = `/mnt/shared/.mxfs_barriers/cwr_write` (a barrier dir, 16 nodes
  concurrently touch nodeN into it → grows shortform→block).
- `xfs_bmap_validate_extent_raw`: "Bmap BTree record corruption in inode 0x1c001b2 data fork";
  `!(flags & XFS_DABUF_MAP_HOLE_OK)` at xfs_da_btree.c:2814 (xfs_dabuf_map); `DLM inode from_disk
  FAILED ino=29360562 rc=-117` (EFSCORRUPTED) → xfs_trans_cancel in xfs_create → Shutting down.
- DECISIVE: "First 16 bytes of corrupted metadata buffer: 0d 00 00 60 00 82 05 00 60 6e 6f 64 65
  37 01 01  ...`....`node7.." — the bytes being decoded as a bmap extent record are actually
  SHORTFORM DIR DATA: `0d`=count 13, and ASCII "node7" is a dirent name. The bogus "extent"
  (Offset 0x6800030004102 startblock 0x80303737b2329 blockcount 0x170101) is just dirent bytes
  misread as a bmbt rec.
- => on-disk inode 29360562 has di_format = EXTENTS/BTREE while its data-fork literal area still
  holds SHORTFORM dir content (count=13 + "nodeN" entries). A format/content mismatch — a raced
  shortform→block (xfs_dir2_sf_to_block) conversion under concurrent 16-node EX adds left an
  inconsistent on-disk inode. DURABLE: even healthy test1 (never shut down) gets "Structure needs
  cleaning" (EFSCORRUPTED) on `ls cwr_write`. test1 didn't shut down only because it didn't read it.

### Why only 1 node shuts down
The corruption is durable on disk, but a node only shuts down when it READS that dir inode while
its own cached image is invalidated (DLM from_disk reload). The node that wrote the bad image, or
nodes with a still-valid cached image, don't re-read it and survive.

### This is the sess39/53-57/84-90 family
"dir-data clobbers inode cluster" / "shortform-dir lost update" / "inode double-alloc" /
"dir2format disize corruption". The fix space: ensure a directory inode's di_format and data-fork
content are never written/read in a torn (mismatched) state across the shortform→block conversion
under concurrent cross-node EX. Likely the FUA-read / DLM reload of the inode-cluster buffer
(sess90 mxfs_buf_has_uncheckpointed_mods, FIX1) does not cover this dir-inode conversion case.

### NEXT (RULE 4)
Reproduce in isolation fast: clean reboot + run cross_write_read alone (or a 16-node concurrent
`touch SHARED/nodeN` where SHARED starts shortform and crosses the sf→block threshold ~8-13 entries).
Instrument the sf→block conversion (xfs_dir2_sf_to_block / xfs_bmap_local_to_extents) + the
inode-cluster FUA reload to catch the moment di_format is updated without the matching data write
(or a stale cached fork is flushed). Then guard. Re-run posix_multi16 (must complete <600s, 0
shutdowns). After: rsync_paired (148%).

Build: 3DC74E7D (fence fix). fence_during_write + crash_consistency + zero_silent_loss all PASS.
Related: [[sess77-fence-during-write-FIXED-foreign-replay-changecount]]
[[sess52-orphan-runtests-contaminates-cluster-phase]] [[sess57-dir2format-disize-corruption-modify-gap]]
[[sess90-fua-reads-logged-not-checkpointed-root]] [[sess87-lessons]]
</body>

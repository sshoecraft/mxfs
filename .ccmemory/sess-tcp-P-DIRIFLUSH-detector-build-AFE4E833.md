---
name: sess-tcp-P-DIRIFLUSH-detector-build-AFE4E833
description: Build AFE4E833: P-DIRIFLUSH detector (xfs_inode.c, before xfs_inode_to_disk) logs incore block0 fsb + dlm_mode per dir iflush. On PASS node2 iflushes…
metadata:
  type: project
---

## Build AFE4E833 (= C180A702 with the P-STALE-IFLUSH detector upgraded to P-DIRIFLUSH). Clean compile. Marker NOT written.

### P-DIRIFLUSH detector (xfs/xfs_inode.c, in xfs_iflush just before xfs_inode_to_disk):
For every multi-node DIRECTORY iflush (EXTENTS/BTREE, extents loaded) logs: ino, dlm_mode, **incore_blk0_fsb** (first extent at offset 0), incore_nx, disk_nx, dir_gen, loaded_gen, relflush, comm. Gated dirwr/instr, capped 3000.

### EVIDENCE (3 runs, all PASS with this build — detector overhead masks the flaky race):
- node2 P-DIRIFLUSH ino=131: ~90-110× ALL `mode=5 fsb=15`. node1: ~3000× `mode=5 fsb=15`.
- **dlm_mode=5 = EX on ALL dir iflushes** → confirms (with P-STALE-IFLUSH-NONEX=0) the stale fork is serialized UNDER EX. A simple "flush requires EX" fence is USELESS.
- fsb=15 = canonical block0 (daddr 120). On a PASS node2's fork is CORRECT (fsb=15). So the fix target is confirmed: keep node2's in-core block0 fsb = 15 (canonical) always.

### NEXT SESSION:
1. The P-DIRIFLUSH iext-scan adds per-iflush overhead (node1 does ~3000 iflushes) that perturbs timing and masks the race — when CONFIRMING the stale flush, run a FAIL and grep node2 P-DIRIFLUSH for `fsb != 15` under mode=5 (that IS the stale-fork serialization). If the detector masks too much, move the scan behind a cheaper gate or only log when incore_blk0_fsb differs from a recorded canonical.
2. Implement the epoch-aware fence: a multi-node dir inode whose in-core block0 fsb is NOT the canonical (or whose fork epoch < current) must NOT serialize its data fork in xfs_iflush — requeue (-EAGAIN, AIL-safe) and trigger a reload to the canonical fork. Caution: cannot naively skip only the fork (core di_nextents/di_size must stay consistent) — skip/requeue the WHOLE inode flush.
3. The deeper reliable-reload fix (mxfs_dlm_reload_inode must reconcile block0 to canonical 120, not node2's self-stale disk image) per [[sess-tcp-FINDING-stale-iflush-is-under-EX-not-NL]].
[[sess-tcp-FIX-DESIGN-fence-stale-dir-inode-fork-flush]] [[sess-tcp-FIX-entrypoints-inode-flush-fence]] [[sess-tcp-ROOT-stale-incore-extent-map-getdents-blk0-daddr]]

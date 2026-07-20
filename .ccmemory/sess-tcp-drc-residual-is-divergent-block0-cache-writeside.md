---
name: sess-tcp-drc-residual-is-divergent-block0-cache-writeside
description: dir_reuse 2/tcp residual (after phantom-EX fix): DIVERGENT block-0 cache. Both nodes destage divergent block-0 versions via xfsaild (100 w/ node1 ent…
metadata:
  type: project
---

## dir_reuse 2/tcp RESIDUAL root (after phantom-EX fix) — PROVEN by content forensics

### Decisive instruments (xfs/libxfs/xfs_dir2_data.c, always-on capped, KEEP while debugging):
- **P-DWR** in xfs_dir3_data_write_verify: counts "node1_f" dirents in EVERY dir block WRITTEN + comm.
- **P-DRD** in xfs_dir3_data_read_verify: same for every dir block READ FROM DISK (cache miss) + comm.
node1 writes 50 data + 50 md5 = 100 "node1_f" names; a block carrying <100 lost node1 entries.

### PROVEN findings:
1. **ALL dir-block writes are by `xfsaild/sda`** (async writeback) — the release-fence synchronous
   xfs_bwrite (mxfs_dir_flush_data_blocks) effectively NEVER fires (mxfs_dir_data_durable sees the
   block already clean/not-in-AIL and releases). Durability rides on async xfsaild.
2. Block 0 lives at daddr=120 or 112 (reused across rm-rf+recreate incarnations). Its on-disk
   content **OSCILLATES**: P-DWR daddr=112 = 83 → 100 → 83 → 100 (all xfsaild). cnt=83 = node2's
   version (missing node1_f1..f18); cnt=100 = node1's version (complete).
3. **In FAILING runs, P-DRD (disk READS) return cnt=83** (comm=ls/bash = the verify-phase + RMW
   reads) → node2 reads STALE block 0 FROM DISK, RMWs it, writes 83 back. So the loss is DURABLE
   on disk (NOT just a read-cache artifact). Both nodes durably agree.
4. **FLAKY**: 2 PASS / 2 FAIL with instruments. lowDRD/lowDWR = 0 on pass runs, >150 on fail runs.
   The P-DRD read-path scan does NOT reliably mask it (it's not a sub-µs heisenbug at this layer).

### MECHANISM: each node holds a DIVERGENT cached copy of block 0 (same reused daddr) and
alternately destages it via xfsaild. Cache is NOT invalidated at the dir-EX handoff:
- drain_evict at acquire found block 0 -ENOENT (P-DE-BLK empty) → its (reloaded) extent map maps
  block 0 to a daddr OTHER than the cached-stale daddr → MISSES the stale buffer. Extent-map/daddr
  inconsistency between acquire-reload time and modify-read time.
- read-hook (xfs_da_read_buf) TRYLOCK-skips (P34-TRYLOCK-STALE 27-46x, blk=0 daddr=112/120/800 AND
  blk=8388608 leaf daddr=2093296) — buffer locked (likely own xfsaild destage in flight).

### FIX DIRECTION (next): RELEASE-side invalidation (GFS2 go_inval pattern) — when a node releases
the dir EX, AFTER the drain confirms data_durable, EVICT (clear XBF_DONE|_XBF_FUA_FRESH) the dir's
cached DATA blocks so this node CANNOT later destage a now-stale version and so its next acquire
cold-reads the peer's image. Insertion: bast_process release path AFTER the durability loop
(xfs_mxfs_dlm.c ~4745) / around the unlock. Blocks are clean post-drain → clear-DONE safe (NOT
xfs_buf_stale — drops rhashtable entry while AIL refs → corruption, sess64). Must handle the
extent-map-daddr issue (the stale buffer may be at a daddr not in the current map → consider
incarnation-keyed or full-fork evict). Validate WITHOUT the P-DWR/P-DRD scans (strip them for the
real run). Build base after phantom-EX fixes: 5E18ACAA (held-check + backstop + P-TCPEX-REACQ +
forensics). Test: `MXFS_EXTRA_MODARGS='inode_mht_ms=300' bash tests/drc_cap2.sh` (dmesg -C first),
run >=4x for flaky confidence. See [[sess-tcp-PHANTOM-EX-root-fix-held-check-was-tcp-noop]].

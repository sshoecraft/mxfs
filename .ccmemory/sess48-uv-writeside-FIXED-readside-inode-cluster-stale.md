---
name: sess48-uv-writeside-FIXED-readside-inode-cluster-stale
description: sess48: uv WRITE-side durable lost-update FIXED (proven raw-disk); READ-side residual = outlier serves stale block-fmt inode cluster after peer block…
metadata:
  type: project
---

## sess48 (ccloop 8ddb16a2) — 2/tcp uv (cache_coherency) deep diagnosis + partial fix

### WRITE-SIDE: FIXED & PROVEN (build has these, KEEP)
Root (PROVEN, raw O_DIRECT dir-block parse + cross-node P-WRACT active-count trace):
durable WRITE-side lost-update. The outlier's deletes (or the peer's) were committed
to log+cache but NEVER destaged to the LUN; the disk dir block stalled at the
intermediate active-count (act=12 = 10 survivors), peer cold-read the stale disk.
TWO gaps, both fixed:
1. **BLOCK-format deletes**: v0.5.1 made `mxfs_dlm_dir_durable_signal` PUBLISH-ONLY (no
   disk I/O). RE-INTRODUCED contention-gated publish-before-notify: in durable_signal,
   `if (i_dlm_dir_gen>0 && fmt in {EXTENTS,BTREE}) { xfs_log_force(SYNC);
   mxfs_dir_flush_data_blocks(dp); }` — caller holds dp ILOCK_EXCL+i_lock WRITE so mode==EX
   (chokepoint NL-skip can't fire) and the block is authoritative. **Do NOT take i_lock
   (no mxfs_drain_ilock_read) — caller already holds it WRITE → down_read_trylock spins
   forever = 150s P132-ILOCK-STUCK self-deadlock (PROVEN: D-state bash xfs_create→
   durable_signal→mxfs_drain_ilock_read).** gen>0 gate keeps solo rsync (gen==0) free.
2. **SHORTFORM deletes** (dir shrinks block→shortform as files deleted; last ~10 deletes
   are fmt=LOCAL, durable_signal no-ops on them): `mxfs_dlm_dir_inode_durable` (shortform
   inode-cluster flush) was gated `!i_mxfs_self_created` in xfs_remove/create/rename. The
   uv dir is `mkdir -p`'d (self_created on one node) yet shared. FIX: gate
   `(!self_created || i_dlm_dir_gen>0)` — fire for contended dirs.

PROOF write-side is fixed: raw O_DIRECT read of the dir inode (both initiators
BYTE-IDENTICAL = transport coherent) shows **di_format=01 (SHORTFORM), mode=0x41ed,
0 files** — the LUN is durably correct. `drop_caches` on the outlier → it then sees 0.

### READ-SIDE: STILL FLAKY (the remaining blocker)
The outlier serves a STALE cached BLOCK-format inode (incore_fmt=2) after the peer's
block→shortform conversion, and cold-reads the freed data block (act=12) → "uv got=10".
- P-DE-ENTER gen=21 loaded=19 (acquire KNOWS stale) but loaded never advances.
- Added reload-on-gen trigger (lookup `mxfs_dlm_dir_consumer_refresh` + readdir
  xfs_dir2_readdir.c): reload if `MXFS_IF_DIR_RELOAD || dir_gen>loaded_gen` (was
  flag-only/evict-ring which is laggy). reload_inode sets loaded_gen=dir_gen on success
  (L7360) so no loop. This took uv 0/3 → **1/3** (helps, not enough).
- REMAINING: outlier's `mxfs_dlm_reload_inode` re-read returns disk_fmt=2 (block) while
  raw O_DIRECT shows di_format=1 (shortform). P91-RELOAD-PROTECT did NOT fire (stale was
  attempted). **fua_disable=0 did NOT help (0/3)** — so NOT the SCST read cache. O_DIRECT
  fresh + xfs_buf stale + drop_caches fixes ⇒ the kernel inode-cluster buffer is served
  XBF_DONE-cached without re-reading; reload's xfs_buf_stale invalidation isn't sticking
  (race / re-validation / wrong im_blkno/im_len?). `mxfs_fua_disable=1` default (sess45).

### NEXT (read-side): pin why reload's inode-cluster re-read serves stale.
Probe mxfs_dlm_reload_inode: log whether the stale_bp lookup hit, whether xfs_imap_to_bp
bio-read vs cache-hit, and dip->di_format vs a coherent plain-bdev read at the same
instant (P31B pattern exists ~L6410 but gated to in-core-mode-0 non-dir; widen to dirs).
Hypothesis: the cluster buffer is re-validated (XBF_DONE re-set) between stale and read,
or im_len mismatch makes xfs_buf_incore miss it. Consider: reload should FUA-re-read the
cluster (force, even under fua_disable=1) for cross-node dir-inode reload.

### TOOLS (in-tree, reuse): tests/uv_disktruth2.sh (2-node peer-poke + leaves DIR live for
raw-read). Probes added this sess (dirwr-gated, off in prod): P-WRACT (active-count+realns
dir-write trace, pal/xfs_buf.c), P-DSIG (durable_signal gate, xfs_mxfs_dlm.c). Raw inode
read: ino159→AG0 agbno=ino>>3 off=ino&7; byte=xfs_data_offset(super@88)+agbno*8*512+off*512.
### REPRO: ./run.sh 2 tcp cache_coherency (uv subtest). dirwr=1 timing HIDES the race
(passes) — ALWAYS validate in production (no dirwr). Build 8B767DA4 (write-side + readside-v1).
Related: [[sess46-UNIFIED-ROOT-pinned-shared-dir-block-merge-dilemma]] [[sess101_lessons]] [[sess69-ondisk-proof-durable-lostupdate]]

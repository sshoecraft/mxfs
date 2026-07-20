---
name: sess22-CONSOLIDATED-criteria-is-full-suite-root-is-stale-inode-bmap
description: sess22 CONSOLIDATION: criteria = full ./run.sh 2 tcp suite (best 13/16). dir_reuse_coherency daddr-0x78 shutdown CONFIRMED = cross-node stale in-core…
metadata:
  type: project
---

## sess22 CONSOLIDATION (corrects this session's earlier framing)

### Criteria scope
"2 node dlm=tcp test 100% successful" = the **full `./run.sh 2 tcp` suite (16 tests)**, not only dir_reuse_coherency. Best result so far (build AFC07F4D, 2d ago) = 13 PASS / 3 FAIL, but VARIABLE (a re-run gave 9/16). The variance IS the blocker. See [[sess-tcp-HANDOFF-deep-inode-wedge-is-last-blocker]] [[sess-tcp-13of16-pass-3-fails-blockalloc-partition-next]]. dir_reuse_coherency is a (deterministic) proxy that exposes the same root.

### CONFIRMED ROOT (RULE 4, live detectors, build 4F45F442 dir_reuse_coherency run)
The clean-slate round-2 FS shutdown (`EFSBADCRC reading dir DATA block daddr 0x78`, which holds /dev/urandom FILE data) is **cross-node stale in-core INODE / in-core BMAP** — the 90-session cache_coherency family. Proven, not inferred:
- `P81-DEXT ... disk_claims_freed=0 verdict=DISK-INODE-DIFFERS=>incore-extent-stale` → in-core BMAP stale (NOT a real on-disk double-free; bnobt is correct).
- `P47-INACT ino=18876321 incore_gen=4258309808 disk_di_gen=4258309809 disk_di_mode=00 verdict=DISK-FREE=>B-stale/double-free` → in-core inode is ONE generation behind disk (freed+reincarnated on disk), held stale-live in-core with a stale extent map.
This matches sess111 (Gemini #2 DEBUNKED the bnobt/AG-meta path as a red herring — async-writeback/SCST-destage lag mis-read as corruption) and sess55 (P55 alloc-over-inode detectors fired 0× — the allocator NEVER double-hands a block). So: **NOT allocator/bnobt double-alloc, NOT AG-data-block partitioning, NOT a dir-format bug.** The milestone memory's "partition DATA-BLOCK allocation" suggestion was SUPERSEDED by the handoff: fix is **inode-recycle / cross-node inode-cache coherency (sess40/48/108/111 lineage).**

### Mechanism (to fix)
A node holds a stale-live in-core inode (old gen / stale bmap) after the inode was freed+reused on disk (peer or own rm-rf reuse, disk gen bumped). Existing guards catch the destructive INACTIVATION free (xfs_inode.c:2208-2289 nlink==0 takes per-inode DLM EX, FUA-reads disk di_mode/di_gen, skips B1 disk-free / B2 gen-mismatch → INACT-SKIP-STALE fires, e.g. ino 1959). The RESIDUAL hole = the stale in-core BMAP is **USED for block resolution/read** (dir_reuse_coherency: dir ino 131 reads its data block via a stale bmap entry → reused daddr 0x78 → file data → EFSBADCRC) OR a non-inactivation free (truncate/bmap_del), OR DISK-LIVE-same-gen A-lost-removal. The reused/reloaded inode's extent map is not invalidated when its disk incarnation advanced.

### sess22 fixes in tree (DEFENSIVE symptom-level; KEEP unless they complicate the root fix)
- FIX1 torn-SF flush skip (xfs/xfs_inode.c xfs_iflush local-data verify-fail → multi-node DIR → error=0 skip + ISTALE_CAW). Prevents the torn-shortform `xfs_dir2_sf_verify` shutdown. Proven to fire (P22-SFTORN-SKIP).
- FIX2 data-scan lookup fallback (xfs/libxfs/xfs_dir2_leaf.c mxfs_dir2_datascan_lookup). Heals the leaf-hash hole. NOTE: it reads data blocks on lookup-miss, so it reaches the bad-CRC block fast (exposes, doesn't cause, the real corruption). Could be reverted if it complicates root work.
Build with both: 4F45F442.

### NEXT (per handoff)
Fix the cross-node inode-cache coherency so a node never USES (read/bmap-resolve/free) a stale in-core inode whose disk incarnation has advanced. Reproduce full `./run.sh 2 tcp` (reboot via tests/reboot_cluster.sh 2 first; LIO target = no SCSI PR, rejects CAW, drops FUA → FS often EIO-wedged at suite end, reboot to recover). Grep P47/P81/INACT-SKIP-STALE at each wedge. Smaller residuals: fence_during_write FPAT (fixed, re-verify), dlm_scaling perf floor (RULE-0 metadata-perf under load).
</body>

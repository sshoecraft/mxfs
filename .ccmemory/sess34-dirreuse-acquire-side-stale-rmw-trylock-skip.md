---
name: sess34-dirreuse-acquire-side-stale-rmw-trylock-skip
description: sess34 REFINED: dir_reuse 2/tcp loss is ACQUIRE-side stale-RMW (leaf/data ARE destaged at release, P34 clean). Prime suspect: xfs_da_read_buf TRYLOCK…
metadata:
  type: project
---

## sess34 REFINED — dir_reuse_coherency 2/tcp root is ACQUIRE-SIDE stale dir-block RMW

Supersedes the release-durability theory in [[sess34-dirreuse-three-faces-slowness-and-leafhole]].
Build with probes: **327ED8B2** (P34-ACQ-SLOW + P34-LEAF-DRAIN + DRCph markers).

### DECISIVE: leaf/data blocks ARE destaged at release (release durability is FINE)
P34-LEAF-DRAIN (added to mxfs_dir_flush_data_blocks, xfs_mxfs_dlm.c:1185) at dir RELEASE:
test2 15× `CACHED=1 needs_flush=0 done=1 dirty=0 in_ail=0 pin=0 delwri=0` (clean = already
destaged by xfsaild), test1 2× CACHED=1 clean + 2× CACHED=0. P21F-RELFLUSH-LEAF=0 (leaf never
needs release-flush BECAUSE it's already clean). → the on-disk dir blocks are CURRENT at handoff.
So the durable dirent loss is NOT a release-side gap. **It is an ACQUIRE-side stale-RMW**: a node
reads a STALE cached dir DATA/LEAF block and RMWs it, dropping the peer's entries, then that write
becomes durable.

### PRIME SUSPECT (concrete, code-identified, UN-tried): xfs_da_read_buf TRYLOCK-skip
xfs/libxfs/xfs_da_btree.c ~3100: the read-time dir-block invalidation does
`xfs_buf_incore(..., XBF_TRYLOCK, &cbp)`. On TRYLOCK FAILURE (buffer locked by I/O or a peer's
drain) it SKIPS the invalidation ("gen stays mismatched, a later read retries") and the subsequent
xfs_trans_read_buf returns the STALE cached XBF_DONE buffer → the RMW builds on stale → dirent loss.
Under this test's HEAVY contention (P-CONVBLK-DENY=80 on test2 = conversion-deadlock thrash) the
dir block is frequently locked → invalidation skipped often → stale-RMW. Fits the timing/contention
-dependent variance. NEXT: instrument a counter for "dir-block invalidation skipped due to TRYLOCK
fail then served XBF_DONE stale" + whether it precedes a loss round; if proven, FIX = don't serve a
gen-mismatched block on trylock-fail (e.g. retry the lock briefly, or invalidate proactively at EX
acquire when no conflicting buf lock is held, instead of lazily at read time).

### SLOWNESS (still a RULE-0 blocker, ~16-20s/round; 24 rds > 300s timeout):
- ~6s dir-131 handoffs (P34-ACQ-SLOW isdir=1, holder-slow bast_process drain; NOT MHT — MHT=0
  refuted, still ~16s/rd, default inode_mht_ms=50 kept).
- **P-CONVBLK-DENY=80** (dlm/dlm.c:2416): PR→EX conversion deadlock denied→EDEADLK; the EDEADLK
  recovery (xfs_mxfs_dlm.c:8696) drops cached lock via BAST drain + re-acquires EX from NL = a full
  expensive cross-node handoff per conversion deadlock. 80/run = major latency. Both nodes do
  concurrent PR(read)→EX(modify) on the shared dir → constant conversion deadlocks. Reducing these
  (acquire EX directly for known-modify ops?) would cut slowness.

### Faces seen this session (extreme variance — run 3-5× before concluding):
run1 timeout ~3 rounds (~100s/rd); run2 leaf-hole r17 (node1_f45-50.md5, lookup_fail=6); run3
(MHT=0) timeout r19; run4 readdir-SHORT r10 (181/200, lookup_fail=0 = data-block loss). All =
acquire-side stale dir-block RMW (data-block variant → readdir-short; leaf variant → lookup_fail).

### Probes in tree (build 327ED8B2, all always-on/ratelimited, safe to keep):
P34-ACQ-SLOW (xfs_mxfs_dlm.c:8661), P34-LEAF-DRAIN (1218-1273 area), DRCph markers
(tests/suite/dir_reuse_coherency.sh). Cluster reset2.sh before every run; dmesg ring WRAPS.
[[sess28-dir-data-block-RDMISS-first-block-clobber]] [[sess34-dirreuse-three-faces-slowness-and-leafhole]]</body>

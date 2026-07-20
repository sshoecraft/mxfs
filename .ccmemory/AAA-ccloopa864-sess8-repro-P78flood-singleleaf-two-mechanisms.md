---
name: AAA-ccloopa864-sess8-repro-P78flood-singleleaf-two-mechanisms
description: sess8: dir_reuse@32/caw live repro (build 6C932BD7). P78-FMT-TORN-FIX floods ino131 every relflush; single-leaf bmbt confirmed (33ext/55blk); failure…
metadata:
  type: project
---

## sess8 (ccloop a864) — dir_reuse@32/caw live reproduction, build 6C932BD7 (0.10.56)

### Criteria: sole gap = dir_reuse_coherency 32/caw (all other 1/2/4/8/16/32 caw cells PASS; tcp_dlm_scaling caw cells are n/a — that test is transport:tcp). 101 caw cells PASS.

### Repro setup (faithful): `env MXFS_DEV=/dev/mapper/mpatha MXFS_TEST_ENV='DRC_STREAM=1' timeout 1800 ./run.sh 32 caw dir_reuse_coherency`. DRC_STREAM streams each node's dmesg to clyde NFS at `tests/tcp/drc_cap/stream_rank${R}.log` (persistent, no ring-rotation loss). Prep converged 107s (32 nodes). Failure deterministic r3-r7 (sess7).

### LIVE EVIDENCE this session:
1. **P78-FMT-TORN-FIX floods ino=131 on EVERY relflush** (comm=dd, comm=bash; nextents climbing 12→14→16→26→29→33→37; fmt extents(2)→btree(3); ili_fields=0x1 CORE-only, forcing=0x8 DBROOT / 0x4 DEXT). MEANING (xfs_inode.c:5536 sess78): xfs_inode_to_disk writes di_format unconditionally but xfs_iflush_fork only rewrites the dinode LITERAL AREA (broot root) when the data-fork bit is in ili_fields; a CORE-only relflush would publish di_format=BTREE over a stale literal area → P78 forces the bit. P78 rewrites only the broot ROOT (in dinode); it does NOT make the child bmbt LEAF blocks durable (that's mxfs_iflush_force_bmbt_durable, xfs_inode.c:5602, single-leaf-only).
2. **single-leaf bmbt CONFIRMED**: P74 shows disk_size=225280=55 blocks, ~33 extents; 33 fits one bmbt leaf (m_bmap_dmxr[0]~254). So sess7's multi-leaf-gap idea is WRONG — the failure is not a multi-leaf escape.
3. **P74-DINEXT-REGRESS floods comm=rm** (rank1 rm-rf): about_to_write_nx=K disk_nx=K+1 leafsum=K, descending 33→16. This is rank1's sequential rm shrinking the dir; P74 is a FALSE-POSITIVE regression flag during legit rm (log-only, does NOT fence). Benign.

### THE FAILURE (writer-side, LUN itself inconsistent): rank1 stalls, 31 peers grow the shared dir ino131, rank1 re-acquires + adopts the coherent dinode (P133-DINO-READSTALE did NOT fire in sess7 → adopt IS coherent), reads a bmbt LEAF at daddr D via xfs_iread_extents, but D on the LUN holds XDD3 (dir-DATA magic) not BMA3 → xfs_bmbt_read_verify CRC-fail → xfs_trans_cancel → shutdown → readdir=0 → barrier stall → 0/32. Because a cache-miss reader also reads D=XDD3 from the LUN, the LUN itself is torn: a peer released with coherent dinode broot→D-as-leaf but D=XDD3.

### TWO candidate writer mechanisms (need failing-daddr evidence to pick):
- (M1) TORN-PUBLISH: one node allocated D as a bmbt leaf, wrote BMA3 in-core, published broot→D durable, but D's leaf destage never landed on LUN so D still holds its PRIOR XDD3 (D was a dir-data block moments before, reused as a leaf by the extents→btree conversion). mxfs_iflush_force_bmbt_durable is supposed to destage D before the dinode but has a gap (leaf buffer reclaimed, or b_ops!=xfs_bmbt_buf_ops during the data→leaf reuse window so the owner-scan skips it).
- (M2) AG DOUBLE-ALLOC ("Bug B"): two nodes allocate D for different roles (leaf vs dir-data) via a stale bnobt across the handoff. BUT mxfs_dlm_invalidate_ag_meta (xfs_mxfs_dlm.c:28231) already stales ALL agf/agi/bnobt/cntbt unconditionally on fresh acquire → M2 should be prevented if it's called on every allocating acquire (call sites 25133, 29870). Leans toward M1.

### NEXT: wait for P15I-CRCFAIL (logs failing daddr D + per-sector CRCs) + shutdown context in stream_rank1.log. Then: (a) dump raw LUN block at D (via a node: dd if=/dev/mapper/mpatha), confirm XDD3; (b) grep peers' streams for who last wrote D (P133-BMBT-RELFLUSH = leaf write; any dir-data write) → distinguishes M1 (one owner, prior content) vs M2 (two owners). Then fix: M1 → generalize iflush_force_bmbt_durable to guarantee the leaf block owned-by-ino is durable even across the data→leaf b_ops reuse window (don't filter solely on current b_ops==bmbt; also catch a block that the in-core broot references as a leaf but whose cached buffer is dir3-data-typed). M2 → ensure invalidate_ag_meta runs on the dir-grow allocation acquire.

### MECHANICS: cluster CLEAN required before run (pkill run.sh/timeout, fuser -k /tmp/mxfs_run.lock, rm lock). Stream files persistent so analyze after failure. Build 6C932BD7 deployed = VERSION 0.10.56.

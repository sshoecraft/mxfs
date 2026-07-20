---
name: sess30-FACEC-bnobt-double-alloc-deep-dive
description: sess30 FACE C CORRECTED: NOT intra-node alloc double-alloc (P55=0×); it's a cross-node daddr-reuse/stale-extent-map clobber (file urandom data over i…
metadata:
  type: project
---

## sess30 (ccloop 8ddb16a2) — FACE C of dir_reuse_coherency 2/tcp: CORRECTED characterization

Build = clean **AB435ACC** (all sess30 experiments reverted). Cluster FS SHUT DOWN from the corruption → next session MUST reboot/reset before any run.

### FACE C symptom (the severest, shutdown-causing, intermittent ~2/3 runs):
"Structure needs cleaning" (EFSCORRUPTED -117); `xfs_inode_buf_verify` fails reading inode cluster **daddr 0xc00**; the buffer's first 128 bytes = **RANDOM DATA** (urandom file content; test does `dd if=/dev/urandom`). `P26-IGET-FAIL dp=131 inum=3072..3076`. So a FILE's data physically sits where inode 3072's cluster should be = **double-OWNERSHIP of daddr 0xc00** (file data extent + inode cluster).

### CORRECTION (supersedes the earlier "bnobt double-alloc" framing in this file's prior version):
It is **NOT intra-node allocator double-allocation**. The always-on (NOT instr-gated) detector `P55-ALLOC-OVER-INODE` (xfs/libxfs/xfs_alloc.c:4092, per-AG 256-ring of this node's inode-chunk extents, scanned on every DATA alloc) and `P55-ALLOC-OVER-CACHEDINODE` BOTH fired **0×** on both nodes during the corrupting run. sess47 double-FREE detectors (INACT-SKIP-STALE/P47/P81) also 0×. This matches [[sess55-faceB-is-M2-stale-bmap-not-allocator]] which ruled out M1 (allocator) for the identical "data-over-inode-cluster" symptom on the 16-node cluster.

### What FACE C actually is (cross-node daddr-reuse / stale-extent-map clobber):
A daddr (0xc00) ends up owned by BOTH a file data extent and an inode cluster, and the **file DATA-path write** (iomap/bio — NOT through xfs_buf) lands urandom over the inode cluster. KEY: file-data writes BYPASS the xfs_buf metadata chokepoint (`mxfs_buf_xfsaild_skip_dir_write` / the bio-submit guards), so a metadata-buffer guard CANNOT catch or prevent FACE C. The double-ownership origin is upstream — candidates:
- CROSS-NODE allocator double-alloc (one node allocs 0xc00 as file data, peer allocs it as an inode chunk, with incoherent AG free-space). NOT ruled out: the only on-disk cross-node alloc check (P55-ALLOC-OVER-DISKINODE) was REMOVED for perf; the local-cache ring only sees THIS node's chunks.
- STALE FILE EXTENT MAP under inode reuse: a file inode's in-core bmap points at a reused daddr now backing an inode cluster → its data write clobbers the inode. (sess55 "M2 stale bmap" class.)
- P117-AGMETA-STALE-CLEAN fires on release for agno=1 bnobt/cntbt → free-space coherency IS imperfect; both nodes allocate in agno=1 (shared/contended).

### DECISIVE NEXT EXPERIMENT (RULE 4; avoid instr=1 — it hides the race at 100×):
1. Re-add the cheap CROSS-NODE check sess55 removed: at DATA-fork alloc (xfs_alloc_vextent_finish, xfs/libxfs/xfs_alloc.c ~4060) plain-read (LIO-coherent) the allocated daddr's di_magic; if 0x494e (live inode) → log `P30-ALLOC-OVER-DISKINODE agno agbno node` ALWAYS-ON capped. Fires ⇒ cross-node allocator double-alloc confirmed (fix = AG free-space cross-node coherency at AG-DLM acquire — verify the bnobt cold-read actually happens for the inode-CHUNK alloc path / agno=1).
2. If it does NOT fire ⇒ stale file extent map: instrument the file-data write path's daddr derivation vs the inode's on-disk bmap under reuse.
3. Sound fix candidate regardless: EVICT-ON-FREE — when a block/extent is freed (xfs_free_extent / xfs_bunmapi), invalidate (xfs_buf_stale) any cached buffer at that daddr cluster-wide, so no stale buffer/extent survives to clobber the reused daddr. A freed block's cached buffer is by-definition dead → sound to stale.

### FULL PICTURE (3 faces, all = stale-cached-state-survives-reuse):
- FACE A (readdir<200): stale dir DATA block RMW'd/flushed.
- FACE B (lookup_fail): stale dir LEAF block.
- FACE C (shutdown): file data over reused-daddr inode cluster (this memory).
Likely common root: cross-node coherency of free-space + cached buffers/extent-maps under heavy rm-rf+recreate REUSE.

### sess30 refuted (don't repeat): pin-drain-extend (block_verify regression), NL-pin-drain (no help; FACE C pre-existing), write-side set-superset discard (GPT refuted), merge (DLM -110). See [[sess30-three-faces-FACEC-double-alloc-is-root]], [[sess30-GPT-NL-refresh-design-and-superset-refuted]], [[sess30-LIO-coherent-and-acq-pin-drain-fix]], [[sess55-faceB-is-M2-stale-bmap-not-allocator]], [[sess47_lessons]].

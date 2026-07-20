---
name: compiled-dirreuse-node1f1-doublealloc-block0-root
description: sess64 compiled: node1_f1 loss = dir logical-block0 double-allocation (block-format, not shortform); fix = epoch-gated disk-block adopt.
metadata:
  type: project
tags: [compiled, sess64, cache-coherency, dir-double-alloc, block0, node1_f1, epoch-adopt, bnobt]
---

## sess64 — node1_f1 loss = dir logical-block0 DOUBLE-ALLOCATION (block-format), fix = epoch-gated disk-block adopt

Central topic: under a concurrent 400-create storm on a freshly-recreated shared dir, rank1's first file `node1_f1` is durably written but ORPHANED because two nodes independently convert the dir sf→block and each allocate their own physical block for logical block0. The peer's extent map wins; rank1's block0 (holding node1_f1) is leaked. This is the sess15 "concurrent sf→block double-alloc" family, now proven at the byte level, and it is the current `cache_coherency` ship blocker.

### Diagnostic progression (RULE 4, all sess64)

1. **Refute sess62 shortform-converter theory** ([[sess64-node1f1-is-blockformat-not-shortform-refutes-sess62]]). node1_f1 loss is DETERMINISTIC: every run, ~every-other-round, dirino=131 stable, 399/400 survive, all peers miss node1_f1 while rank1 serves it from its un-dropped in-core dir cache after drop_caches ⇒ durably absent on disk for peers. Ran `sfm_dbg=1`: `P-SFM-DROP`, `P-SFM-READD`, `P64-SFM-SKIP-BASE`, and always-on `P56-RELOAD-MERGE` ALL fired **0×**. So `reload_inode` never hits the LOCAL/shortform branch — the shared dir is already BLOCK format by the time any reload runs (converts within the first few of 400 creates). The 3-way shortform merge is NOT the node1_f1 path; node1_f1 lives in a `fmt=data` block (P-DIRWR owner=131 fmt=data; data blocks have no count tail so active=-1). Conclusion: BLOCK-format data-block content lost-update, not the sess62 shortform converter.

2. **Decisive byte-level root** ([[sess64-DECISIVE-ROOT-node1f1-orphaned-in-double-allocated-block0]]). Added always-on tracer P64-N1F1 in the dir DATA/BLOCK buffer WRITE path (`pal/linux/xfs_buf.c`, after P-DIRWR), scanning each written dir block for the exact dirent byte pattern `\x08node1_f1` (namelen=8 + name; excludes node1_f10-19 namelen=9 and node1_f1.md5 namelen=12), logging owner+daddr+present+comm, capped 6000 so it survives the ring (unlike the dirwr=2 firehose which wraps the dmesg ring before the early conversion window). Round 18, dir ino 131, distinct daddrs written for owner=131:
   - **daddr=120: present=1** (49 writes, comm=dd/xfsaild) — node1_f1 IS durably written here by rank1.
   - **daddr=2093296: present=0** (194 writes), plus 2093304/4186520/6279744/6279760 all present=0 — node1_f1 ABSENT.
   
   node1_f1 is durable but in daddr=120; the dir's logical block0 that all peers write into (and cold-read verify sees) is a DIFFERENT physical block daddr=2093296 that never held node1_f1. The winning on-disk extent map maps block0→2093296; daddr=120 is orphaned/leaked. Not a content RMW lost-update, not a shortform merge bug — dir logical-block0 double-allocation.

3. This also explains the coupled **bnobt double-free** shutdown: rm-rf (or an extent-map adopt) frees BOTH block0 allocations → `bno+len>gtbno` at `xfs_free_ag_extent` (`xfs_alloc.c:2428`). AG-affinity angle: `preferred_ag = node_slot % agcount`, so the two block0 daddrs live in DIFFERENT AGs; forcing all nodes onto ONE block0 removes the divergence.

### Fix path ([[sess64-FIX-PATH-enable-disk-block-adopt-prevents-block0-doublealloc]])

Two reload guards already exist in `xfs_mxfs_dlm.c`:
- **P43 / format-revert guard** (~line 7629): in-core BLOCK + disk LOCAL, same incarnation, EX-held → keep in-core block, refuse the shortform (prevents a same-node second `xfs_dir2_sf_to_block` re-init). Reverse direction only.
- **Forward adopt** = `mxfs_dir_modify_adopt_disk_format` (`xfs_mxfs_dlm.c:3044`), driven at modify pre-lock by `mxfs_dir_adopt_block`: in-core SHORTFORM + disk BLOCK (a peer already converted) → reload the disk BLOCK fork BEFORE modifying, adopting the peer's block0 (incl node1_f1) instead of running our own `xfs_dir2_sf_to_block` that allocates a SECOND block0. THIS is the double-alloc prevention — but it ships **`int mxfs_dir_adopt_block = 0;` (DEFAULT OFF, line 2753)**. That is why the double-alloc is unprevented. (sess62's "REFUTED" of adopt was a LOCAL-vs-LOCAL content-gap scenario, a DIFFERENT case than this proven BLOCK0-daddr divergence — do not treat it as refuting this fix.)

Concrete next-session fix:
1. Re-enable / re-work `mxfs_dir_modify_adopt_disk_format` so on a dir modify where in-core is SHORTFORM (or in-core block0 daddr != disk block0 daddr) and disk is BLOCK for the same incarnation, the node reloads/adopts the disk BLOCK fork (extent map → peer's block0 daddr) and MERGES its own pending shortform entries into that adopted block additively, rather than allocating a new block0.
2. Trigger off the monotonic per-dir EPOCH (sess64 plumbing, in tree) as the reliable "a peer converted since our base" signal — the lossy evict-ring/edge-bit missed it ~80%.
3. **CRITICAL SAFETY**: must NOT free the orphaned block0 inline (double-free → the bnobt `bno+len>gtbno` shutdown). Reconcile the extent map to the peer's block0; let the orphan be leak-then-reclaimed by the owning node, NOT a cross-node free. Verify with the P64-N1F1 tracer that the WINNING block0 daddr carries present=1 for node1_f1 on all nodes.

Why the naive block-format epoch adopt is NOT yet viable: rebuilding the extent map (`xfs_idestroy_fork`) and/or bypassing the P33/P43 SHRINK guards adopts a smaller/divergent image and frees blocks inconsistent with the in-core bnobt → the same `bno+len>gtbno` double-free shutdown during rm-rf (INTERMITTENT — build **77251EF3** ran 1/24 clean once, shut down next run; the di_gen incarnation gate did NOT eliminate it). Block-format adopt needs AG-free-space coherence first.

### Build markers (sess64)
- **F20F3CAC** — baseline behavior (epoch adopt OFF) + epoch plumbing (observe-only, P64-EPOCH-OBS) + P64-N1F1 tracer (KEEP, capped, the key diagnostic) + P64-SFM-SKIP-BASE. 2/tcp coherence PASS; criterion NOT met.
- **56E5E61C** — baseline-equivalent + epoch plumbing + P64-SFM-SKIP-BASE probe (sfm_dbg-gated, harmless). 2/tcp coherence PASS.
- **77251EF3** — block-format epoch adopt ENABLED experiment; 1/24 clean then bnobt double-free shutdown. Not viable without AG-free-space coherence.

Epoch PLUMBING is in tree and correct (KEEP); block-adopt remains DISABLED/observe-only pending the safe additive-merge + orphan-reconcile-without-free rework.

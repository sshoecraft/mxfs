---
name: sess64-FIX-PATH-enable-disk-block-adopt-prevents-block0-doublealloc
description: sess64 FIX PATH: dir block0 double-alloc (orphans node1_f1) is unprevented because mxfs_dir_adopt_block defaults OFF (=0). The in-core-SHORTFORM+disk…
metadata:
  type: project
---

## sess64 FIX PATH — node1_f1 / block0 double-alloc: enable disk-BLOCK adoption, epoch-gated

### The code gap (found by reading, RULE 4)
Root (proven sess64): dir logical-block0 is DOUBLE-ALLOCATED across nodes — rank1 converts sf→block allocating block0@daddr=120 (with node1_f1), a peer independently converts sf→block allocating block0@daddr=2093296 (its entries), peer's extent map wins on disk, node1_f1 orphaned. (See [[sess64-DECISIVE-ROOT-node1f1-orphaned-in-double-allocated-block0]].)

Two reload guards exist:
- **P43 / format-revert guard** (xfs_mxfs_dlm.c ~7629): in-core BLOCK + disk LOCAL (same incarnation, EX-held) → KEEP in-core block, refuse the shortform (prevents a SAME-NODE second xfs_dir2_sf_to_block re-init). This handles the reverse direction.
- **Forward adopt** = `mxfs_dir_modify_adopt_disk_format` (xfs_mxfs_dlm.c:3044), driven at modify pre-lock by `mxfs_dir_adopt_block`: in-core SHORTFORM + disk BLOCK (a PEER already converted) → reload the disk BLOCK fork BEFORE modifying, so we ADOPT the peer's block0 (incl node1_f1) instead of running our OWN xfs_dir2_sf_to_block that allocates a SECOND block0. **THIS is the double-alloc prevention — and it is `int mxfs_dir_adopt_block = 0;` (DEFAULT OFF, line 2753).** That is why the double-alloc is unprevented.

### NEXT-SESSION FIX (concrete)
1. The forward disk-BLOCK adopt is the right mechanism but was left OFF (sess62 "REFUTED" was for a LOCAL-vs-LOCAL content gap, a DIFFERENT scenario than this proven BLOCK0-daddr divergence). RE-ENABLE / re-work `mxfs_dir_modify_adopt_disk_format` so that on a dir modify where in-core is SHORTFORM (or in-core block0 daddr != disk block0 daddr) and disk is BLOCK for the SAME incarnation, the node reloads/adopts the disk BLOCK fork (extent map → peer's block0 daddr) and MERGES its own pending shortform entries into that adopted block (additive) rather than allocating a new block0.
2. Use the monotonic EPOCH (sess64 plumbing, in tree) as the reliable "a peer converted since our base" trigger so the adopt fires exactly when needed (the lossy evict-ring/edge-bit missed it 80%).
3. CRITICAL SAFETY: this must NOT free the orphaned block0 inline (that double-frees → the sess64 bnobt `bno+len>gtbno` shutdown). Reconcile the extent map to point at the peer's block0; let the orphan be handled by the owning node / leak-then-reclaim, NOT a cross-node free. Verify with the P64-N1F1 tracer (KEEP, pal/linux/xfs_buf.c) that after the fix the WINNING block0 daddr carries present=1 for node1_f1 on all nodes.
4. Watch for the AG-affinity angle: different nodes allocate block0 from different AGs (preferred_ag = node_slot % agcount) → the two block0 daddrs are in different AGs. Forcing all nodes to adopt ONE block0 removes the divergence.

### Build F20F3CAC on disk = baseline behavior (epoch adopt OFF) + epoch plumbing + P64-N1F1 tracer + P64-SFM-SKIP-BASE. 2/tcp coherence PASS. Criterion NOT met. See [[sess64-DECISIVE-ROOT-node1f1-orphaned-in-double-allocated-block0]] [[sess64-GPT-design-per-dir-monotonic-epoch-replaces-handoff]].</body>

---
name: sess68-MAPDIVERGE-rules-out-extentmap-loss-is-pure-datablock-RMW
description: sess68: full per-block daddr compare at modify-prelock (P68-MAPDIVERGE) finds maps AGREE (=0) → RULES OUT extent-map divergence at modify. 4/tcp loss…
metadata:
  type: project
---

## sess68 — MAPDIVERGE rules out extent-map divergence; loss is pure data-block content RMW

Final refinement of [[sess68-FINAL-epoch-not-enough-datablock-durability-next]].

### Implemented sess67's documented MERGE-adopt (full per-block daddr compare)
In `mxfs_dlm_dir_modify_reload_prelock` (xfs/xfs_mxfs_dlm.c ~3120, gated `mxfs_dir_modify_extent_adopt`): for an EXTENTS-format dir, decode the disk inline extents (xfs_bmbt_disk_get_all) and compare EACH (startoff,startblock,blockcount) to the in-core map via xfs_iext_lookup_extent; on ANY divergence reload+adopt (post_release=true) BEFORE the modify. Replaces the inert sess67 count-compare. Probe P68-MAPDIVERGE.

### RESULT (RULE 4, decisive): P68-MAPDIVERGE = 0 (NEVER fired) across a full failing 4/tcp run.
→ At EVERY modify-prelock, this node's in-core dir extent map MATCHES the disk extent map (same per-block daddrs). **The extent maps do NOT diverge at modify time.** Yet the run FAILED with a CONTIGUOUS whole-block loss (node1_f10, node1_f10.md5, node1_f11 — one data block's worth of node1's entries, durably gone on all nodes).

### CONCLUSION (high confidence, narrows the search):
The 4/tcp dir_reuse residual is **a pure dir-DATA-BLOCK CONTENT lost-update at a daddr ALL nodes agree on** — NOT extent-map divergence (ruled out by MAPDIVERGE=0), NOT extent-map durability (gap-B confirms inode durable, P68-GROWREL-VERIFY DURABLE 48/48), NOT cached-block survival (drop_caches → owner-evict collected=0). A node writes data block K (agreed daddr) to the platter MISSING a peer's just-committed entries; it lands last.

### So the bug is in the data-block RMW serialization/coherency itself:
A node RMWs block K from a base lacking the peer's entries, despite: DLM EX serialization, the release fence (Invariant 1, data_durable required to break the drain loop), and force_evict (drops clean + destaged-in-AIL cached blocks before modify). Candidates NOT yet disproven:
1. The cold re-read of block K after a peer's release returns STALE (SCST/LIO target write-cache not pierced by the FUA read) — even though drop_caches+verify reads the platter, the MODIFYING node's mid-test re-read may hit the target cache. TEST: a write-side probe comparing block K's in-core content to a FUA re-read right before RMW.
2. force_evict KEEPS block K as in-AIL-UNDESTAGED (its own un-written work) when in fact a peer superseded it — but Invariant 1 should have destaged it at the prior release. Verify the prior release actually destaged block K (not just the inode).
3. A genuine concurrency window in the EX handoff where two nodes' block-K dirty images both exist (DLM double-grant was refuted sess62 P-DOUBLEGRANT=0, but re-check under this specific contiguous-block-loss signature).

### NEXT STEP (RULE 4): add an ALWAYS-ON, CHEAP write-side probe in the dir data-block modify path: when a multinode dir's data block is about to be logged/written after an entry ADD, stamp it with (node-slot, monotonic-seq) in a b_mxfs field; on a peer's read/RMW, if the block's stamp shows a peer wrote a HIGHER seq than the base this node read, a lost-update is imminent. OR instrument the exact create of node1_f10..f11 vs the block K daddr + which node last wrote K. Heisenbug caution: instr=1 masks the race (~100x slow) — use cheap always-on stamps, NOT synchronous FUA probes in the hot path.

### BUILD `59AED037` (HEAD): gap-B (KEEP, proven) + P68-DATAINIT/GROWREL-VERIFY probes (KEEP, cheap) + owner-evict (gated, moot here) + MAPDIVERGE per-block compare (code kept, `mxfs_dir_modify_extent_adopt` default 0 — found no divergence, FUA-per-modify is pure perf cost). Shipped-proven baseline still 91962D4A. Wall for 24-round 4/tcp ≈ 313s. Cluster healthy test1-4; test5-8 up.

CRITERION NOT MET (4/tcp dir_reuse_coherency; 1/2 PASS, 8 untested).</body>

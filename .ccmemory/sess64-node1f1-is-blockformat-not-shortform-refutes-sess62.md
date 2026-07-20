---
name: sess64-node1f1-is-blockformat-not-shortform-refutes-sess62
description: sess64 REFUTES sess62: node1_f1 loss is NOT the shortform merge (all SFM/P56 probes fired 0×) — it's a deterministic BLOCK-format data-block content…
metadata:
  type: project
---

## sess64 — node1_f1 is a BLOCK-format data-block loss (refutes sess62 shortform-converter theory)

### Deterministic + decisive evidence this session
- node1_f1 (rank1's FIRST file) loss is **DETERMINISTIC** (every run, ~every-other-round, all peers miss it, 399/400, dirino=131 stable). Tractable.
- node1_f1 is **durably absent on disk**: rank1 SEES it (serves from its un-dropped in-core dir cache after drop_caches), ALL peers cold-read disk and MISS it ⇒ a peer's RMW clobbered it on disk, or it was never published through the sf→block conversion.
- **REFUTES sess62**: ran with sfm_dbg=1 — `P-SFM-DROP`, `P-SFM-READD`, `P64-SFM-SKIP-BASE`, and the always-on `P56-RELOAD-MERGE` ALL fired **0×** for this workload. So reload_inode NEVER hits the LOCAL/shortform branch — the shared dir is already **BLOCK format** by the time any reload runs (it converts sf→block within the first few of 400 concurrent creates). The 3-way shortform merge is NOT the node1_f1 path. node1_f1 lives in a `fmt=data` block (P-DIRWR owner=131 fmt=data; data blocks have no count tail so active=-1).
- So node1_f1 is a BLOCK-FORMAT data-block content lost-update (sess15 family), NOT the sess62 shortform-converter.

### Why the epoch adopt can't be the fix here (sess64)
The epoch-driven disk-superset adopt for BLOCK-format dirs rebuilds the extent map (xfs_idestroy_fork) and/or bypasses the P33/P43 SHRINK guards → adopts a smaller/divergent image → frees blocks inconsistent with the in-core bnobt → `bno+len>gtbno xfs_alloc.c:2428 xfs_free_ag_extent` double-free shutdown during rm-rf (INTERMITTENT — build 77251EF3 ran 1/24 clean once, shut down next run). The incarnation gate (di_gen match) did NOT eliminate it. So the block-format adopt is NOT viable without AG-free-space coherence.

### The real remaining mechanism (unproven — needs a firehose-surviving probe)
A peer RMWs block0 of the block-format dir from a base missing node1_f1, and writes it durable. But every clobber detector is CLEAN (P-DOUBLEGRANT=0, P106-STALE-EX=0, P-SF-DURABLE-FAIL=0). The pinned-stale-block-skip in mxfs_dir_drain_evict_data_blocks is the prime suspect (drain_evict skips dirty/pinned/in-AIL blocks via XBF_TRYLOCK), but the release fence claims to unpin. dirwr=2 content traces WRAP the dmesg ring before the early conversion window, so they don't capture the loss moment.

### NEXT (next session)
1. Add a CHEAP always-on probe in the dir2 DATA-block write path (pal/linux/xfs_buf.c P-DIRWR site, or xfs/libxfs/xfs_dir2_data.c) that EXACTLY matches the dirent name "node1_f1" (namelen=8, not prefix — avoid f10-f19/.md5) and logs PRESENT/ABSENT + node + daddr + crc on every block0 write. This survives the firehose (fires rarely) and catches the exact write that drops node1_f1 (which node, from what base).
2. OR instrument node1_f1's publish-durability through the sf→block conversion: is node1_f1 in the FIRST data block when it's first written durable, and by whom?
3. The block-format data-block lost-update is the sess15/sess46 "pinned shared dir block merge dilemma" — reliable fix needs either bounded release-side unpin guarantee for the SPECIFIC block, or a force-free disk-read merge of the block (sess63 attempt-2 corrupted at 4 nodes — debug that).

### Build state: epoch PLUMBING is in tree + correct (KEEP). Block-adopt DISABLED (observe-only P64-EPOCH-OBS). Current build 56E5E61C = baseline-equivalent behavior + plumbing + P64-SFM-SKIP-BASE probe (sfm_dbg-gated, harmless). 2/tcp coherence tests verified PASS. See [[sess64-WIN-incarnation-gated-epoch-adopt-1of24-no-corruption]] [[sess62-HANDOFF-next-fix-is-namesetset-union-merge-epoch-scoped]] [[sess15-ROOT-concurrent-sf-to-block-conversion-double-alloc]].</body>

---
name: sess68-BOUND-single-block-dir-fails-simplest-repro
description: sess68 KEY BOUND: 4/tcp dir_reuse FAILS even with tiny single-BLOCK dirs (DRC_NFILES=3, 24 entries, no multi-block grow). Residual is pure 4-node con…
metadata:
  type: project
---

## sess68 KEY BOUNDING RESULT — the 4/tcp residual is pure single-block RMW coherency, not grow

### Experiment (RULE 4): `DRC_NFILES=3 DRC_ROUNDS=40 ./run.sh 4 tcp dir_reuse_coherency`
3 files/node × 4 nodes × 2 (data+md5) = 24 entries → the shared dir stays **BLOCK format (single dir block, no conversion to multi-block LEAF, no grow)**. **STILL FAILS** (nodes_pass=0/4).

### IMPLICATION (big simplification): the 4/tcp dir_reuse residual does NOT require:
- multi-block growth, BLOCK→LEAF conversion, extent-map divergence, higher-block daddr allocation, bmbt, or any of the grow machinery chased sess36/62/67.
It reproduces with the SIMPLEST possible case: **4 nodes concurrently create into ONE shared single-block directory, with rank1 rm-rf+recreating it each round (inode-# reuse).** A durable single-entry coherency failure results (~varies; with 50 files it's a count loss / RDMISS, with 3 files the readdir count was OK so it was the leaf-hash lookup_fail arm — the block-format dir's internal hash/data consistency).

### So the next session should debug the MINIMAL repro:
`DRC_NFILES=3 DRC_ROUNDS=30 ./run.sh 4 tcp dir_reuse_coherency` — fewer entries = far less log volume = dmesg ring won't rotate = clean ground truth is finally achievable. Focus on ONE dir block (BLOCK format, daddr=120) under 4-node concurrent xfs_dir2_block_addname RMW + rm-rf reuse. The whole question reduces to: how does a concurrent add/rm-rf sequence on a single shared dir block durably drop one entry (or corrupt its internal hash) at 4 nodes when 2 nodes pass?

### This session's confirmed facts (carry forward):
- gap-B FIXED+KEEP (extent-map durability at release; P68-GROWREL-VERIFY DURABLE 48/48) — but NOTE: with single-block dirs the extent map is trivial, so gap-B is irrelevant to this minimal repro. gap-B is still a real fix for the grown-dir case.
- REFUTED: extent-map divergence (MAPDIVERGE=0), cached-block survival (drop_caches), read-side stale/target-cache (fua_disable=0 still fails), DLM double-grant.
- The loss is write-side, same-incarnation, durable.

### Likely root for the MINIMAL repro (hypothesis for next session):
A BLOCK-format dir stores dirents + a leaf-hash array + bestfree in ONE block. 4-node concurrent xfs_dir2_block_addname under EX-handoff + rm-rf reuse: a node RMWs the block from a base that is stale in its INTERNAL structure (hash array vs data entries), OR the block-format dir's reuse (rm-rf → sf → block reconversion) re-inits/zeroes the block (sess36 data_init-zero family — but for BLOCK format the conversion is xfs_dir2_sf_to_block / leaf_to_block). The sess36/sess43 sf↔block double-conversion divergence (two nodes each convert the reused dir) is the prime suspect at this scale. Check P42-SFCONV / P43 / P62-SF2BLK-CALLED in the minimal repro.

### BUILD `590E2E89` (gap-B + probes). Cluster healthy test1-4 mounted. CRITERION NOT MET. [[sess68-FUA-refutes-readside-loss-is-writeside-same-incarn]] [[sess36-PROVEN-datainit-zeroes-live-block0-root]] [[sess43... sf-block-revert-guard]]</body>

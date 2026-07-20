---
name: sess43-RESIDUAL-is-growth-conversion-divergence-forceblock-already-on
description: sess43: dir_force_block already DEFAULT ON (eliminates sf->block divergence) yet 8/tcp fails → residual = block->leaf->node GROWTH-conversion diverge…
metadata:
  type: project
---

## sess43 (ccloop) — connecting the round-1 finding to the precise residual root. Read with [[sess43-KEY-loss-is-round1-pure-concurrent-create-not-reuse]] [[sess43-INFRA-and-multimode-trace-state]].

### dir_force_block is ALREADY default ON (current build) and 8/tcp STILL fails
`int mxfs_dir_force_block = 1;` (xfs_mxfs_dlm.c:6374, sess67 default ON; guard mxfs_dir_should_force_block = multi-node + DIR + shortform). So every fresh storm dir (rm-rf'd+recreated each round) is born BLOCK format at the single-node mkdir → the cross-node **sf→block** conversion divergence (the historical-sess43 fix that made 2/tcp PASS) is ALREADY eliminated. Yet 8/tcp dir_reuse still loses a dirent ~33%, reproducing at ROUND 1 (fresh dir).

### Therefore the residual root = the NEXT conversions: block→leaf→node GROWTH during the 800-entry concurrent fill
force_block only fixes the FIRST conversion (sf→block, moved to single-node mkdir). As 8 nodes concurrently add 800 entries, the dir must still convert **block→leaf** (when block0 fills) and **leaf→node** (as it grows), each ALLOCATING new data/leaf blocks and re-laying-out block0. Under concurrent EX handoffs, a node that converts (splits block0 / adds a data block) releases, and the next node must RELOAD the new multi-block layout before adding; if it reloads a STALE layout (durable-read-staleness across the handoff — the dland-proven stale-base RMW), it lays out divergently and a dirent is durably lost. This is the SAME stale-base-RMW mechanism, localized to the growth-conversion boundary. (Connects [[sess42-SYNTHESIS-block0-split-is-double-sf-conversion-lineage]] — but it's block→leaf, not sf→block, since force_block already handles sf→block.)

### Fix directions to try next (RULE 4, instrument first):
1. **Extend force to a higher initial format**: born the multinode dir directly in LEAF/NODE format with enough data blocks pre-allocated for ~800 entries, so NO block→leaf→node conversion happens during the create wave → no growth-conversion divergence. (Hack-ish but tests the hypothesis: if pre-grown dirs PASS, the growth conversion IS the root.)
2. **Serialize+drain the conversion**: ensure a block→leaf / leaf→node conversion of a shared multinode dir fully drains the new layout durable AND the next acquirer cold-reads the new block COUNT/map before adding (the acquire-evict must cover the NEWLY-allocated blocks, which the extent-map-bound evict may miss right after a conversion — connects the sess43 owner-scan evict, which was inert because the stale base was pinned/dirty; at a conversion the new blocks ARE the node's own dirty work, so this is subtle).
3. Instrument the conversion points (xfs_dir2_block_to_leaf, xfs_dir2_leaf_to_node) for the storm dir: log when each fires + the block layout before/after + which node, correlate with the victim's loss round (use tests/drc_trace.sh + 64K dland ring).

### Build 5F0C1457 keeper-functional (dir_owner_scan=0; force_block=1 as always; only diagnostic P13/ring changes). Criterion NOT met.</body>

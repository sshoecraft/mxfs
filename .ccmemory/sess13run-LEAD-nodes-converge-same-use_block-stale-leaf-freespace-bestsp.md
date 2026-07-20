---
name: sess13run-LEAD-nodes-converge-same-use_block-stale-leaf-freespace-bestsp
description: sess13(ccloop) STRONG LEAD: correlation shows multiple nodes' leaf-addname converge on the SAME use_block index (=1, same daddr) — their leaf freespa…
metadata:
  type: project
---

## sess13 (ccloop) — STRONG LEAD: stale LEAF freespace (bestsp[]) → same-use_block convergence

### Correlation evidence (build B2FAE263, probes in saved per-round dmesg)
Round 8 lost node3_f1 (data file, creator test3). Grepping the placement probes:
- test3 placed node3_f1 via P13-STALEREAD at use_block=1 daddr=10468032 (one round) and use_block=1 daddr=16745872 (another).
- Earlier (same build, prior run) test2 placed node2_f16.md5 at use_block=1 daddr=10468032.
=> Multiple nodes' xfs_dir2_leaf_addname select the SAME data-block index (use_block=1) → the SAME daddr. In a multi-block leaf dir each node SHOULD spread across blocks; converging on block 1 means the LEAF freespace table (bestsp[] / ltp->bestcount, read from the leaf block in xfs_dir2_leaf_addname ~L1005-1048) is STALE — every node believes block 1 has the most/only free space and piles into it, then the stale per-block data read (xfs_dir3_data_read L1168, returns near-empty bestfree → P13-STALEREAD) makes them place at low offsets, overwriting each other / peers' durable entries on handoff.

### Refined root model (ties together ALL session evidence)
The dir_reuse loss is LEAF-format freespace+data coherency on EX handoff: (1) the LEAF block's bestsp[] free-space-per-data-block table is stale across handoffs (nodes pick the same use_block); (2) the selected data block's xfs_dir3_data_read serves a stale near-empty image (bestfree wrong); → addname places at a low offset onto a slot a peer durably used → 1+ dirents clobbered. Both the leaf bestsp[] AND the data block must be coherently re-read on a cross-node dir-EX acquire. Current force_evict/epoch refresh the DATA blocks (mxfs_dir_evict_data_blocks walks data extents) but may NOT reliably refresh the LEAF block's bestsp[] view, and/or the data re-read still serves stale (the undestaged-skip / cached-XBF_DONE-served-without-reread path).

### NEXT (RULE 4):
1. CONFIRM: instrument xfs_dir2_leaf_addname to log the LEAF block's bestsp[use_block] + ltp->bestcount the node used, cross-node — if two nodes in the SAME round both see block 1 as most-free while it is actually full, the stale-bestsp[] root is proven.
2. Check whether mxfs_dir_evict_data_blocks / the acquire refresh evicts/re-reads the LEAF block (xfs_dir3_leaf_buf_ops) — the P21S-EVICTSKIP-LEAF (sess21) showed the LEAF evict being SKIPPED. The leaf bestsp[] staleness may be the EVICTSKIP-LEAF gap. FIX direction: on a cross-node dir-EX handoff, force a coherent re-read of the LEAF block (bestsp[]) too, not just data blocks — but guard against reverting this node's own uncommitted leaf updates (dirty/in-AIL skip).

### Session totals: 7 builds (final B2FAE263, all probes + off-by-default levers, default==40AC2A0C), 14+ cluster runs, 2 GPT consults, 16 memories. Winning config 399/400, corruption eliminated. 8/tcp unrun. Criterion NOT met.
See [[sess13run-P13-STALEREAD-mostly-normal-need-correlate-specific-lost-name-with-probes]] [[sess21-EVICTSKIP-LEAF]] (P21S-EVICTSKIP-LEAF) [[sess13run-WINNING-CONFIG-fua-plus-epoch-adopt-399of400]].</body>
</invoke>

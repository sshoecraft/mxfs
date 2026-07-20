---
name: sess65-CHURN-block0-daddr-instability-plus-stale-base-writes
description: sess65 churn finding: within ONE round node1_f1 is written present=1 to MULTIPLE block0 daddrs (120, 4188360) AND present=0 to others (8372968 from s…
metadata:
  type: project
---

## sess65 — block0 churn: per-node divergent block0 + stale-base writes (round-2 trace)

### Decisive trace (build 0B2188CC, dir_lower_block0_wins=1+epoch_adopt=1, test1/rank1, round 2, P64-N1F1 daddr+present):
- node1_f1 written **present=1 to daddr=120** (82x) AND **present=1 to daddr=4188360** (112x) — TWO different physical block0s both CONTAIN node1_f1.
- node1_f1 written **present=0 to daddr=8372968** (97x) AND **present=0 to daddr=14654472** (7x) — block0 writes from a STALE base WITHOUT node1_f1.
- Only ONE P42-SFCONV conversion for ino=131 that round (sf_count=11, dlm_mode=5/EX), and its base HAD node1_f1 (P62-SF2BLK). So the extra block0 daddrs are NOT extra conversions.

### Interpretation
Within ONE incarnation the dir "block0" is written to MULTIPLE physical daddrs — each node maintains its OWN extent[0] (its own physical block0) and writes its block0 there. node1_f1 lives in test1's block0 lineage (120 -> 4188360, both present=1). A PEER writes its block0 (8372968) from a stale base lacking node1_f1. The inode's on-disk extent[0] = whoever iflushes inode-131 LAST; when a peer's node1_f1-less block0 wins, node1_f1 is lost. The earlier "one ext0 per incarnation in RELEASE logs" was the SETTLED value; the WRITES show the churn before settling.

### Why the sess65 guards didn't fire (both 0x)
- P65-LOWERB0-KEEP (reload guard, disk_b0>incore_b0 -> keep lower): the in-core extent[0] transitions through a path that is NOT mxfs_dlm_reload_inode (test1's block0 goes 120->4188360 with no reload-guard hit). Candidate paths to instrument next: xfs_bmap/iext remap during dir grow, dir consumer-refresh evict + re-iget, or the union-merge re-writing block0. ADD A PROBE at every dir-inode extent[0] mutation (old->new fsb + stack) to pin it.
- P65-IFLUSH-FENCE (iflush, incore_b0>disk_b0): 0x — flush-time local cluster buffer is cross-node incoherent, so divergence invisible at flush.

### Conclusion unchanged: the robust fix is the DURABLE canonical block0 record (docs/canonical_block0_fix_plan.md) — ONE physical block0 per incarnation, first/lowest publisher wins, all nodes adopt it at conversion (prelock, reliable master signal) so no node ever writes a divergent block0. The per-node-divergent-extent[0] + stale-base-RMW churn cannot be fixed by read-side keep-stale guards alone.

### SAFE BASELINE: srcversion 2E0FDC34 = all sess65 module params default OFF (dir_lower_block0_wins, dir_iflush_fence, dir_epoch_adopt, dir_pending, dir_merge, dir_force_block, dir_adopt_block); xfs_iops.c restored pristine. Probes retained. Criterion NOT met.
See [[sess65-FINAL-block0-flipflop-flush-buffer-incoherent-canonical-record-needed]] [[sess65-HANDOFF-two-stage-node1f1-extent-split-then-content-clobber]].</body>

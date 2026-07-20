---
name: sess65-convgate-0x-epoch-prelock-cant-serialize-conversion-need-dlm-record
description: sess65: epoch-gated prelock convert-gate fired 0x (shortform+epoch-advanced window doesn't align with conversion timing); epoch_adopt drops converter…
metadata:
  type: project
---

## sess65 — why no XFS-layer guard serializes the double conversion; DLM record required

### CONFIRMED ROOT (round-2 trace, build 0B2188CC): TWO nodes convert ino=131 in the SAME round — test1 AND test3, each dlm_mode=5/EX, each allocating its OWN block0. Both block0s get node1_f1; later stale-base block0 RMWs (P64-N1F1 present=0 at 8372968/14654472) drop it and a node1_f1-less block0 wins inode-131's extent[0]. = classic dir-block0 double-allocation.

### Every XFS-layer serialization angle tried this session FIRED 0x or regressed:
- **P65-EPOCH-CONVGATE** (prelock: in-core LOCAL + dir epoch advanced > valid_epoch -> reload+adopt before converting): fired 0x. The prelock-shortform + epoch-advanced window does NOT align with the conversion moment — when a node is at the prelock with in-core LOCAL, the epoch has not yet advanced (the racing peer's conversion commit and our prelock check interleave such that we don't see it); by the time the epoch is up, our in-core is already block (we converted) so the LOCAL gate misses.
- **P65-LOWERB0-KEEP** (reload: keep lower block0): fired 0x — block0 transitions don't go through mxfs_dlm_reload_inode.
- **P65-IFLUSH-FENCE** (iflush: skip higher block0): fired 0x — flush-time local cluster buffer cross-node incoherent.
- **dir_epoch_adopt=1**: ACTIVELY HARMFUL — drops the converter's OWN entries on adopt (round 5/10 lost node1_f1..node1_f15, all of test1's first 15 files). "Adopt harder" regresses.
- **dir_pending replay**: cold-read timing gap (fires 0x).
- **dir_merge / dir_force_block default-on**: corrupts 2/tcp.

### CONCLUSION (firm): the conversion race is decided in a window where NO disk-read, epoch-query, reload, or iflush guard has a coherent, synchronously-checkable "a canonical block0 already exists" signal. The signal must live in the DLM master (set in-memory at the FIRST converter's commit, delivered on every grant) and be checked AT the conversion under EX. This is docs/canonical_block0_fix_plan.md (GPT-5.5 option C). It is the REQUIRED fix; implement it next (parallel the dir_epoch per-lock plumbing in dlm/dlm.c + v5_mount.c; publish at xfs_dir2_sf_to_block; query+adopt at the prelock; iflush fence as backstop).

### SAFE BASELINE: srcversion 621FD271 = ALL sess65 module params default OFF (dir_epoch_convert_gate, dir_lower_block0_wins, dir_iflush_fence, dir_epoch_adopt, dir_pending, dir_merge, dir_force_block, dir_adopt_block) = baseline behavior; xfs_iops.c pristine. With no module args this is the known baseline. Criterion NOT met (node1_f1 lost: 4/tcp 0/4, 2/tcp intermittent). All sess65 probes + gated infrastructure retained for the DLM-record work.
See [[sess65-CHURN-block0-daddr-instability-plus-stale-base-writes]] [[sess65-FINAL-block0-flipflop-flush-buffer-incoherent-canonical-record-needed]].</body>

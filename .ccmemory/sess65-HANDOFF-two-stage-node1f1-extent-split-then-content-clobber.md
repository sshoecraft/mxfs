---
name: sess65-HANDOFF-two-stage-node1f1-extent-split-then-content-clobber
description: sess65 HANDOFF: node1_f1 is TWO bugs — Stage1 dir-block0 extent-map SPLIT (FIXED by dir_epoch_adopt=1, convergence PROVEN) + Stage2 block0 CONTENT cl…
metadata:
  type: project
---

## sess65 HANDOFF — node1_f1 is a TWO-STAGE bug; Stage 1 solved, Stage 2 open

### Criterion NOT met. Build on disk = FEF626A4A9D94B0D (with NO module args = BASELINE behavior; all new flags default OFF).

### THE BUG IS THE SAME AT ALL NODE COUNTS
node1_f1 (rank1's first file) durably lost in dir_reuse_coherency. 4/tcp: EVERY round (readdir=399/400). 2/tcp: INTERMITTENT (~round 20, readdir=199/200). The criteria.json "2/tcp dir_reuse PASS" was a LUCKY run — the bug exists at 2 nodes too, just rarer. So fixing node1_f1 fixes 1/2/4/8 together. corruption=0 in the pure-baseline case (no shutdown); the loss is a silent dirent drop.

### TWO STAGES (both PROVEN this session)
**Stage 1 — dir logical-block0 extent-map SPLIT** (double-alloc). Baseline: nodes' inode-131 data-fork extent[0] DIVERGE (rank1=daddr120/AG0, peers=high-AG daddrs); cold reader sees whichever iflush landed last; node1_f1 (only in daddr120) orphaned.
→ **FIXED by dir_epoch_adopt=1** (PROVEN: all 4 nodes' ext0 converged to daddr=120). New module_param `dir_epoch_adopt` (xfs_mxfs_dlm.c ~2755): on a post_release reload with dir epoch advanced > valid_epoch, sets genuine_handoff=true forcing the disk-extent-map adopt. Pure fork swap (no block free) → no bnobt corruption from the adopt itself.

**Stage 2 — block0 CONTENT clobber** (the RESIDUAL after Stage 1). With extent map converged on daddr=120, node1_f1's DIRENT is STILL missing from block0=120's content on disk. A write-side durable lost-update: a node RMWs block0=120 from a stale base missing node1_f1 and writes it. The block-dir union-merge (dir_merge=1, mxfs_dir_merge_peer_into_tp, FUA-reads disk block0 + re-adds peer entries before RMW) did NOT fix it and added minor corruption. Likely the clobbering node reads a STALE-CACHED block0 (not FUA) OR rank1's node1_f1 write isn't drained to disk before the peer's RMW reads it. This is the sess17/sess79/sess84 block-dir durable lost-update family — investigate dir-DATA-block FUA re-read / drain-before-release for the SINGLE converged block0.

### DO NOT (refuted/regressed this session)
- **force_block=1 + merge=1 default ON → CORRUPTION at 2 nodes** (Internal error, force_shutdown). Avoid this combo.
- **dir_epoch_adopt LOCAL-only** (earlier variant) made node1_f1 lost EVERY round (adopts peer's node1_f1-less block0 harder). The all-formats epoch_adopt is better (converges) but doesn't restore content.
- **Pending-dirent replay** (dir_pending=1, mxfs_dir_pending_add/replay) CANNOT fix it: the losing node observes the loss only at COLD-READ (drop_caches), with no transaction to replay into; lookup finds node1_f1 present in-core during creates so replay skips. Built + gated OFF (infrastructure for later).
- **Truncate-path staleness guard** (P65-STALE-TRUNC): fired 0x (staleness is in bmbt CONTENTS not dinode header). REMOVED.

### NEW MODULE PARAMS (all default 0; build FEF626A4): dir_epoch_adopt, dir_pending. Existing: dir_merge, dir_force_block, dir_adopt_block (all 0). Probes: P65-EPOCH-ADOPT, P64-EPOCH-OBS, P64-N1F1 (byte tracer), P62-REL-DIREXT (ext0 daddr+gen), P42-SFCONV.

### NEXT SESSION PLAN
1. Run `MXFS_EXTRA_MODARGS='dir_epoch_adopt=1' ./run.sh 4 tcp dir_reuse_coherency` — confirm Stage 1 stays converged (ext0 all daddr=120), isolate Stage 2.
2. Fix Stage 2 content clobber: trace WHEN block0=120 loses node1_f1 (P64-N1F1 present flag on daddr=120 writes). Ensure the clobbering node FUA-re-reads block0 (not stale cache) before RMW AND rank1 drains node1_f1 before EX release. Likely a dir-DATA-block cache-coherency / drain-ordering fix, NOT the union-merge.
3. Verify no 2/tcp regression after each change (2/tcp is also intermittently affected).
See [[sess65-replay-timing-gap-adopt-at-coldread-not-create]] [[sess65-GPT-design-pending-dirent-replay-fixes-node1f1]] [[sess64-DECISIVE-ROOT-node1f1-orphaned-in-double-allocated-block0]].</body>

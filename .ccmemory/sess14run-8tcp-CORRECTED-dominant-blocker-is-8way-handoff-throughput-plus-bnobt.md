---
name: sess14run-8tcp-CORRECTED-dominant-blocker-is-8way-handoff-throughput-plus-bnobt
description: sess14(ccloop) 8/tcp CORRECTED: dir is fmt=2 extents/LEAF (NOT btree — NODE-format hypothesis WRONG). 8-node failures are dominated by 8-way handoff…
metadata:
  type: project
---

## sess14 (ccloop) — 8/tcp blocker CORRECTED & consolidated

### Correction (P26-RDDIR evidence)
The 800-entry dir is fmt=2 (XFS_DINODE_FMT_EXTENTS), nextents=9, disk_size=24576 (6 data blocks) = LEAF format, NOT NODE/btree. My earlier "NODE-format coherency" hypothesis is REFUTED. Multiple NFILES=50 runs at 8 nodes gave DIFFERENT outcomes:
- DRC_ROUNDS=4, NFILES=50: PASS 8/8 (P26 healthy: nextents=9, disk_size=24576).
- DRC_ROUNDS=24, NFILES=50 (run A): FAIL — readdir=0/800 failrounds recorded on every node incl creator (real coherency miss).
- DRC_ROUNDS=24, NFILES=50 (run B): FAIL 0/8 but NORESULT (empty node logs = killed at TEST_TIMEOUT=300s; the 24-round 8-way workload didn't finish in time).
- NFILES=10: PASS 8/8.

### Consolidated 8-node blockers (by frequency/impact)
1. **8-way dir-EX handoff THROUGHPUT** (dominant). dir_reuse 24 rounds × 8-way contention × EXP=800 exceeds 300s TEST_TIMEOUT → NORESULT. Same root as tcp_dlm_scaling 2/8 and dlm_scaling 7/8. The per-release Invariant-#1 settle (required, ~22ms) × the handoff count at 8-way is the cost (see [[sess14run-tdscaling-cost-is-settle-loop-required-asynckick-minor-help]]). 4-node fits 300s (~205s); 8-node ~2× workload+contention → over.
2. **Coherency-miss variance** (intermittent): readdir=0/800 on ALL nodes incl creator after drop_caches — the creator loses its own large dir on cold re-read. Systemic when it happens (not partial). Likely a per-run cluster-state/FUA-read issue, not deterministic. Needs capture-at-failure (P26 was healthy on the passing runs; need P26 when readdir=0).
3. **bnobt corruption** in crash_consistency (node-kill recovery): survivor journal-replay vs live AG free-space → bnobt double-free. The long-standing bnobt family.

### INFRA: 8-node runs frequently WEDGE the mxfs module (rmmod busy) after FS-shutdown/heavy runs → next prep fails "device busy". Clean: umount+rmmod all 8; if still WEDGED, `virsh -c qemu:///system destroy/start` the node. Budget extra time for 8-node prep.

### Criterion: 1/tcp ✅ 2/tcp ✅ 4/tcp ✅ 8/tcp ✗. NOT met. Build AA8C4934.
The highest-leverage 8-node fix is dir-EX handoff throughput (helps dir_reuse timeout, tcp_dlm_scaling, dlm_scaling at once). See [[sess14run-8tcp-10of17-clean-run-bnobt-is-the-blocker-DABUF-gone]].

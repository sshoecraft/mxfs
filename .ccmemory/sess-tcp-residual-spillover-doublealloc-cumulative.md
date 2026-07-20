---
name: sess-tcp-residual-spillover-doublealloc-cumulative
description: After slot fix (A3E2842C), residual: full ./run.sh 2 tcp suite soak FAILs (3766 EIO errs) because cumulative load fills each node's affine AG → alloc…
metadata:
  type: project
---

## Residual after the slot-claim fix (build A3E2842C)
Individual coherency tests + dlm_fairness all PASS (7/7 + dlm_fairness 3/3 via harness). BUT
the FULL `./run.sh 2 tcp` (all tests on ONE mount, cumulative) fails soak (ran last):
dur=30s ops=4910 errs=3766 dmesg_hits=0. Root: test1 FS shut down DURING an earlier test —
`xfs_inactive_ifree → imap_to_bp -5 → Metadata I/O Error, Shutting down` on inodes in AG3.
Flood of `INACT-SKIP-STALE ino=... agno=3 incore_mode=0100644 disk_mode=00 ... avoid double-free`
+ repeated `P82-ADD agno=3` = cross-node inode DOUBLE-ALLOCATION in AG3 (in-core live vs on-disk
free; later incore_gen != disk_gen = peer reallocated). soak then ran on the EIO-dead FS → 3766
errs; dmesg_hits=0 because shutdown predated soak's marker.

## Mechanism
node-affinity (xfs_dialloc_pick_ag) sends each node's allocations to its OWN AG (slot0→AG0,
slot1→AG1). Under cumulative suite load each affine AG FILLS, so xfs_dialloc's
for_each_perag_wrap_at SPILLS into the next AG — which can be the PEER's / a shared AG (AG3) →
both nodes allocate from AG3's inobt with stale cross-node views → double-alloc → shutdown.
The slot fix removed the GUARANTEED AG0 collision (fixed dlm_fairness) but data-heavy cumulative
load still spills+collides. This is the long-standing double-alloc family in a milder form.

## Candidate fixes (next)
1. STRICT AG partition: each node spills only within its OWN disjoint AG set
   (owned(a) = a % N == slot % N, N=active node count). Needs a live-node-count accessor
   (dlm active_nodes.count, dlm.h:101). Constrain xfs_dialloc passes to owned AGs; final
   unconstrained pass only on true partition-ENOSPC. RISK: core allocator change.
   Note: m_mxfs_max_nodes=64 (MXFS_MAX_NODES) > agcount=50, so can't partition by max_nodes.
2. Coherent spillover-AG handoff: fix the AG-DLM release-durability (force-release-on-2s-timeout
   + meta_pending counter LEAK, P55-STUCKMETA xfs_mxfs_dlm.c ~12045). Harder (90-session problem).

## Caveat: prior session's [[sess-tcp-MILESTONE-full-suite-8pass-0fail]] saw soak PASS in the
full suite once (build F22321, both-slot-0) — so it's load/timing-dependent, may be intermittent.
Re-confirm reproducibility before the risky allocator change. Cluster: test1 FS was EIO-wedged
(shutdown) — needs VM reboot to recover. See [[sess-tcp-FIX-noncaw-slot-claim-unique-ags]].

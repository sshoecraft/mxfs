---
name: sess12run-CLEAN-BUILD-4tcp-baseline-two-real-bugs
description: sess12(ccloop) clean F0D7B279 4/tcp baseline: 13 PASS, 4 FAIL = 2 REAL bugs (dir_reuse loss + corruption-0x8 shutdown) + 2 contamination cascades.
metadata:
  type: project
---

## sess12 (ccloop 4cb2d0a2) — TRUE 4/tcp baseline on CLEAN build F0D7B279 (default params)

CRITICAL CORRECTION to the resume: the prior recorded 4/tcp failures (crash_consistency 0/4 etc) were caused by the cluster running an EXPERIMENTAL build (890C3B13, dir_coherent_modify=1) left by sess11. After power-cycling test1-4 and running `./run.sh 4 tcp` on the CLEAN local build F0D7B279 (defaults: dir_epoch_adopt=0, dir_coherent_modify=0, dir_force_evict=1, dirrefresh=0, dir_leaf_rebuild=0):

### 13 PASS
precond_readiness, cache_coherency, strong_consistency, posix_multi, mmap_coherency, zero_silent_loss, dlm_fairness, dlm_membership, scaling_curve, dlm_scaling, rsync_paired, **crash_consistency (4/4 — was 0/4 on the experimental build = experimental build was the regression)**, soak.

### 4 FAIL = 2 REAL bugs + 2 contamination cascades
1. **dir_reuse_coherency 0/4 — REAL.** Single-dirent durable readdir loss: `readdir=399/400 lookup_fail=0`, missing entry is ALWAYS a node1 `.md5` file (node1_f42.md5, node1_f49.md5), and ALL nodes incl. node1 (rank=1, the creator) miss it. No shutdown. This is the deep sess11 cross-node dir-data-block free-slot double-allocation bug. epoch_adopt=1 is a FLUKE fix (code comment xfs_mxfs_dlm.c:3081 confirms ~1/5 pass).
2. **fence_during_write 0/4 — REAL.** Nodes 2/3/4 hit `XFS (sda): Corruption of in-memory data (0x8) detected at xfs_defer_finish_noroll+0x2b6 (xfs_defer.c:721)` / `xfs_trans_cancel (xfs_trans.c:1061)` → **Shutting down filesystem**. Same corruption-0x8 family as the known tcp_dlm_scaling `__xfs_trans_commit:890` shutdown. A DIFFERENT bug from dir_reuse — AG/bmap deferred-op metadata corruption under sustained concurrent cross-node writes to a shared hot dir.
3. **fault_netpartition 1/4 — CONTAMINATION** (nodes 2/3/4 already shut down by fence_during_write; "still writable" / "healed node sees partition-window writes got=0" because FS is down).
4. **tcp_dlm_scaling 1/4 — CONTAMINATION** (same; runs after fence shutdown).

### Strategy
- 2/tcp = 17/17 (CLAUDE.md sess58). The 4/tcp delta is two concurrent-multinode metadata-coherency bugs that only manifest at 4+ nodes.
- The 2 contamination cascades will clear once fence_during_write stops shutting down nodes. So the criterion reduces to fixing **(1) dir_reuse durable loss** and **(2) corruption-0x8 shutdown under sustained concurrent writes**.
- Cluster recovery: nodes get fenced/shutdown by fence_during_write; power-cycle test1-4 via `virsh -c qemu:///system destroy+start` then re-run. ALSO add harness inter-test recovery later so a node-shutdown test can't cascade.
- Repro: `./run.sh 4 tcp dir_reuse_coherency` standalone (~175s); faster `tests/tcp/drc4_capture.sh 24` (dirwr=2 ~55s). For corruption-0x8: `./run.sh 4 tcp fence_during_write` standalone (after reset).

Criterion NOT met. See [[sess11run-ROOTCAUSE-PROVEN-cross-node-dirblock-freeslot-double-allocation]] [[sess11run-DECISIVE-dirent-absent-at-durable-signal-entry-handoff-during-create]].
</body>

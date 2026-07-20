---
name: sess59-4node-tcp-16of17-dir-reuse-coherency-fails
description: sess59: 4-node TCP (build 60EFBE5E) = 16/17. sess58 inode-lock fixes HOLD at 4 nodes (all pass 4/4). Sole fail = dir_reuse_coherency: readdir-miss +…
metadata:
  type: project
---

## sess59 — 4-node TCP scaling result (LIO infra, build 60EFBE5E)

`./run.sh 4 tcp` = **16 PASS / 1 FAIL**. Log /tmp/suite_4tcp_115825.log.

### sess58 transport-independent fixes HOLD at 4 nodes
All sess58-related tests pass 4/4: tcp_dlm_scaling, cache_coherency,
crash_consistency, fence_during_write, fault_netpartition, posix_multi,
mmap_coherency, zero_silent_loss, dlm_fairness, dlm_membership,
scaling_curve, dlm_scaling, rsync_paired, strong_consistency,
precond_readiness, soak. The AG↔dir ABBA + ilock_nowait resurrection
fixes (xfs/xfs_inode.c) are not node-count-fragile. Good.

### Sole failure: dir_reuse_coherency (0/4, systematic — NOT a sess58 regression)
- Test: tests/suite/dir_reuse_coherency.sh. NFILES=50, ROUNDS=24,
  EXP = 2*NODES*NFILES → **400 entries/round at 4 nodes** (was 200 at 2).
- Symptom (identical on ALL 4 nodes): round 14 `node3_f18.md5` and
  round 18 `node4_f35` **missing_from_readdir (399/400) but lookup_fail=0**
  → entry is in leaf-hash (lookupable) but absent from readdir
  enumeration. Real coherency violation (peer entry written+sync'd+barriered,
  reader's cold-cache readdir misses it). Even the creating node misses
  its OWN entry from readdir after drop_caches.
- Also TIMED OUT: killed at round 18/24, no RESULT line (TEST_TIMEOUT=300).
  Doubled verify work (400 cold-cache lookups/round) + eviction-ring storm
  blew the budget. ROUNDS/timeout not scaled for node count.
- dmesg: NO EFSCORRUPTED/shutdown/corruption. Shared dir ino=5481 under
  `EVICT-RING-DIRMOD` storm (gen 123→163 in seconds, "N callbacks
  suppressed"); fmt=1 (block). DLM cache 99% hit, no AG-yield wedge.
  P-SFDIR-REVERT / P62-RELOAD-FORK-SHRINK / P56-RELOAD-MERGE probes firing.

### Significance
2-node TCP PASSES dir_reuse_coherency (it was in sess58's 17/17). 4-node
FAILS it. So the dir-coherency mechanism that got 2 nodes to 100% is
**concurrency-fragile — doesn't scale past 2 nodes.** This is the same
transport-independent dir lost-update / readdir-staleness family that
dominated the CAW work (sess79-92 cache_coherency ship blocker) →
fixing it helps CAW too (it IS the CAW ship-blocker family).

### Recommendation
Do NOT run 8-node yet (EXP=800 → worse timeout + same bug amplified).
Decide strategy first: dig dir_reuse_coherency at 4-node TCP (RULE 4),
vs pivot to SCST/CAW where this family is the historical blocker anyway.
See [[infra-lio-for-tcp-scst-for-caw-rationale]],
[[project-caw-priority-enterprise-vmware-proxmox-san]].

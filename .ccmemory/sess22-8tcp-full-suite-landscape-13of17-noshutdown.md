---
name: sess22-8tcp-full-suite-landscape-13of17-noshutdown
description: sess22(ccloop) full ./run.sh 8 tcp on keeper DFDBAAFE = 13 PASS / 4 FAIL, ZERO shutdowns on any node, NO cascade. Reorder fix transformed sess21's sh…
metadata:
  type: project
---

## sess22 (ccloop) — full 8/tcp landscape on keeper DFDBAAFE

`TEST_TIMEOUT=480 ./run.sh 8 tcp` (clean reboot, build DFDBAAFE, leaf_rebuild OFF):
**13 PASS / 4 FAIL. ZERO 'Shutting down' on ALL 8 nodes. NO cascade.**

### PASS (13): precond_readiness, strong_consistency, posix_multi, mmap_coherency, dlm_fairness, dlm_membership, scaling_curve, dlm_scaling, rsync_paired, **crash_consistency 8/8** (was sess21's CASCADE culprit — now PASSES), fence_during_write, soak, **tcp_dlm_scaling 8/8**.

### FAIL (4) — all PURE COHERENCY, no shutdown, no cascade:
- **cache_coherency 0/8** (all nodes fail a coherency check — early in suite, later tests still PASS = no cascade)
- **zero_silent_loss 0/8**
- **dir_reuse_coherency 0/8** (leaf-hash hole + round-1 create-visibility miss; flaky — passes ~50% standalone)
- **fault_netpartition 7/8** (1 node; the partition test's own residual)

### SIGNIFICANCE:
The sess22 reorder-remove fix ([[sess22-FIX-remove-reorder-eliminates-dirty-cancel-shutdown]]) eliminated the dirty-cancel SHUTDOWN class. Result: the 8/tcp suite went from sess21's shutdown-cascade (11/17, crash_consistency hang cascading into the tail) to NO shutdowns at all + 13/17 with 4 ISOLATED coherency fails. This is the cleanest 8/tcp state recorded. crash_consistency + tcp_dlm_scaling now pass 8/8.

### REMAINING for criteria (1/2/4/8 tcp 100%):
4 deep coherency bugs at 8 nodes (cache_coherency, zsl, dir_reuse, fault_netpartition). These are the 130-session coherency core (leaf-block lost-update / dir-block lost-update / unlink-visibility family). NEXT: cache_coherency 0/8 is the highest-value (all-nodes-fail = deterministic-ish, not flaky like dir_reuse) — capture its failure mode (uv unlink-visibility? cross-write-read?). Likely shares the leaf/data lost-update root with dir_reuse. See [[sess22-FINAL-keeper-DFDBAAFE-and-remaining-deep-bugs]].

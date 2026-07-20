---
name: sess20-tds-makespan-grantqueue-already-FIFO-cause-is-commit-serialization
description: sess20(ccloop) tcp_dlm_scaling makespan: grant queue is ALREADY FIFO (dlm/dlm.c promote_waiters sorts by queued_at) — fairness is NOT the lever. Root…
metadata:
  type: project
---

## sess20 (ccloop) — tcp_dlm_scaling makespan: fairness ruled OUT, cause is commit serialization

### Investigated the lever-1 (grant fairness) from [[sess20-VERIFIED-1tcp-2tcp-green-4tcp-8tcp-blocked-by-tds-makespan]]:
`dlm/dlm.c::promote_waiters` (line ~619) ALREADY sorts waiters by `queued_at` oldest-first = **FIFO grant ordering** (waiter_cmp line 599), stops at first incompatible to prevent starvation. So the grant queue is fair by design — **fairness is NOT the makespan lever**. Do not re-investigate DLM grant fairness.

### The rank spread (rank8=33s, rank1=126s) comes from the CACHED-EX FAST-PATH + mht-defer, not unfair queueing: a node holding the dir-EX cached rips through many rounds WITHOUT re-queuing (fast-path), and `mxfs_dlm_mht_defer_bast` (xfs_mxfs_dlm.c:7681) keeps it cached for the full mht_ms on a peer BAST. So work proceeds in mht-sized batches; a node that finishes early exits, leaving the tail node serialized behind everyone's batches.

### ROOT of the 3× high-mht slowdown (PROVEN by measurement): makespan/round = 105ms at mht=300 vs 36ms at mht=100 (same 1200 total rounds). The extra cost is **COMMIT SERIALIZATION**: at high mht one node holds and runs its 150 rounds' create+rename+rm journal commits BACK-TO-BACK SERIALLY (each sync commit waits for the prior). At low mht rounds from different nodes INTERLEAVE so their journal commits PIPELINE (overlap I/O latency) → 3× faster wall. This is intrinsic to the mht batching mechanism.

### CONSEQUENCE: to fit the 60s window at 8 nodes, tcp_dlm_scaling fundamentally needs LOW mht (interleaved pipelined commits). dir_reuse needs HIGH mht (rare handoffs mask its incomplete-drain coherency bug). NO single mht. The ONLY clean resolution = fix dir_reuse coherency at low mht (complete the dir/AG release drain: stale leaf FIXED, residual = extent-map + AG free-space double-alloc, sess38-47 class). A makespan-only fix would require pipelining journal commits even under single-node batching (deep journaling change, risky) OR an idle-hold cap that raises dir_reuse handoff frequency (breaks it). See [[sess20-SCOPE-sole-blocker-is-8node-tcp_dlm_scaling-makespan]].
</body>
</invoke>

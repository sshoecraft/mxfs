---
name: sess14run-8tcp-dir_reuse-is-CORRECT-passes-at-600s-budget-not-coherency
description: sess14(ccloop) KEY: 8/tcp dir_reuse is CORRECT — 24 rounds PASS 8/8 zero fails with TEST_TIMEOUT=600 (fixed 300s was too short). Failure was THROUGHP…
metadata:
  type: project
---

## sess14 (ccloop) — 8/tcp dir_reuse is CORRECT; the failure is budget/throughput

### PROVEN
`TEST_TIMEOUT=600 ./run.sh 8 tcp dir_reuse_coherency` (24 rounds, NFILES=50, EXP=800) = **PASS 8/8, ZERO failrounds**. The default fixed `TEST_TIMEOUT=300` killed it mid-run (NORESULT 0/8). So 8-node dir_reuse coherency is FINE — the earlier readdir=0/800 failrounds were near-timeout artifacts / contamination, not a real NODE-format or 8-way coherency bug.

### Root reframe
The dir_reuse workload is **O(N)**: EXP=2×T×NFILES (800 at 8 nodes vs 400 at 4). 8-node wall ≈ 2× the 4-node wall (~400s vs ~205s) for 2× the work — MXFS scales ~LINEARLY, not pathologically. But run.sh uses a FIXED `TEST_TIMEOUT=300` for ALL node counts, so an O(N) test inevitably times out at high N. Per CLAUDE.md RULE 0 ("budget = infra + workload(native×2)"), the budget SHOULD scale with the workload — a fixed budget for an O(N) workload is the harness bug (same class as the coord_barrier -W bug I already fixed). Scaling the budget to the actual workload is implementing RULE 0 correctly, NOT "widening to pass."

### Implication
Many 8-node "failures" (dir_reuse timeout, possibly fence/netpartition/soak) are likely budget artifacts, not bugs. The REAL 8-node bugs are narrower:
- **tcp_dlm_scaling**: has its OWN internal WINDOW=60s assertion (in the test script, not TEST_TIMEOUT) — 8×150=1200 serialized ops vs 60s. A genuine DLM throughput scaling assertion (2× the 4-node serialized ops, same window). Hard.
- **bnobt** corruption in crash_consistency (node-kill journal-replay vs live AG free-space) — a real correctness bug.

### NEXT
Run full `TEST_TIMEOUT=600 ./run.sh 8 tcp` to separate budget-artifacts from real bugs. Then: (a) if dir_reuse/fence/netpartition/soak pass at 600s, implement a node-count-scaled per-test budget in run.sh (RULE-0-correct); (b) tackle bnobt + tcp_dlm_scaling 60s-window as the real remaining 8-node bugs.
See [[sess14run-8tcp-CORRECTED-dominant-blocker-is-8way-handoff-throughput-plus-bnobt]] [[sess14run-tdscaling-cost-is-settle-loop-required-asynckick-minor-help]].

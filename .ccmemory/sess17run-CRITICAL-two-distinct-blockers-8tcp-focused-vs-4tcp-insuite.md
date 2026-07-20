---
name: sess17run-CRITICAL-two-distinct-blockers-8tcp-focused-vs-4tcp-insuite
description: sess17(ccloop) CRITICAL: TWO distinct dir_reuse blockers — 8/tcp fails FOCUSED (round-5 lost-update), 4/tcp PASSES focused but fails IN-SUITE (contam…
metadata:
  type: project
---

## sess17 (ccloop) — TWO distinct dir_reuse blockers (build 9AF854E6 fork-adopt)

Validated the fork-adopt fix [[sess17run-FIX-forkadopt-handoff-round1-fixed-round5-residual]] is SAFE (no focused regression) and uncovered a SECOND blocker:

### Blocker A — 8/tcp dir_reuse fails FOCUSED (the genuine lost-update)
`./run.sh 8 tcp dir_reuse_coherency` (clean reboot, focused) = FAIL 0/8 at ROUND 5 (single-entry data-block revert, P13-STALEREAD). This is the real durable lost-update. fork-adopt fixed round 1; round 5 residual unsolved (epoch levers refuted — timeouts).

### Blocker B — 4/tcp dir_reuse fails IN-SUITE only (contamination)
- `./run.sh 4 tcp dir_reuse_coherency` (clean reboot, FOCUSED) = **PASS 4/4** on 9AF854E6 (and was PASS on baseline E3CDB9F1). So the fork-adopt fix does NOT regress 4/tcp.
- `./run.sh 4 tcp` (FULL suite) = 12 PASS then **dir_reuse FAIL 0/4** + fence_during_write/fault_netpartition/soak/tcp_dlm_scaling all FAIL (cascade). The 12 tests before dir_reuse (precond..crash_consistency) all PASS, so something in that prefix CONTAMINATES dir_reuse (leftover /mnt/shared state / inode-daddr reuse collision / DLM residue). Same "tests pass standalone, fail in-suite" pattern noted in CLAUDE.md sess49.
- => For the criterion (FULL ./run.sh 1/2/4/8 tcp = 100%), Blocker B must ALSO be fixed — it's a cross-test state leak, INDEPENDENT of the round-5 lost-update.

### Implications for next session
1. Blocker A (8/tcp focused round-5 lost-update): the hard durable bug. Directions in [[sess17run-HANDOFF-forkadopt-kept-round5-residual-next-granularity]] (per-handoff reliable signal / targeted single-block refresh; NOT per-modify epoch — timeouts).
2. Blocker B (in-suite contamination): NEW focus. Run `./run.sh 4 tcp` and bisect which prior test contaminates dir_reuse (insert dir_reuse earlier, or run pairs). Likely a leftover-state / inode-reuse cross-test leak. Check run.sh per-test cleanup of /mnt/shared.
3. fork-adopt fix (9AF854E6) = SAFE KEEP (fixes 8/tcp round 1, no focused 4/tcp regression).

Reboot ALL nodes clean (virsh destroy+start) between runs. Criterion NOT met; marker NOT written.</body>

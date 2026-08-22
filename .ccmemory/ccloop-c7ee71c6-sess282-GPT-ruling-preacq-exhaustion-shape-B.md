---
name: ccloop-c7ee71c6-sess282-GPT-ruling-preacq-exhaustion-shape-B
description: sess282 RULE-5 ruling: preacq exhaustion fix = shape B (unbounded clean op-level retry, remove EAGAIN→ETIMEDOUT entirely); C (BAST-defer pregrant win…
metadata:
  type: project
---

# sess282 RULE-5 ruling — preacquire-exhaustion fix shape (rename/remove spurious ETIMEDOUT)

Defect: 32-way same-dir rename storm → P271-PREACQ-EXHAUST on 30/32 nodes, mv returns ETIMEDOUT on 4/32 (cache_coherency rv subtest, 0.11.499 board run 20260814T195525Z).

## Ruling (GPT, gpt-5.6-sol)
- **Shape C (pregrant BAST-deferral window) REJECTED**: it is semantically an AG hold across entry-ILOCK reacquisition → recreates the forbidden I2 edge (owner: protected AG → waits entry ILOCK; peer: entry ILOCK → waits AG revoke). No value of T proves both I2 safety and progress. Also non-monotonic for multi-AG sweeps.
- **Shape B LANDS**: inner handoff budget stays 8 (batching/telemetry boundary, NOT a failure threshold). On exhaustion: verify trans clean, drain AG state, unlock joined inodes, cancel, capped randomized escalating backoff, check shutdown/fence, retry op internally — UNBOUNDED. Contention -EAGAIN must NEVER escape the operation, never convert to -ETIMEDOUT, and no high-count safety valve either (that's still the defect, just rarer). Observability instead: ratelimited warn, per-AG counters.
- Termination classes kept distinct: shutdown → -EIO/shutdown error; genuine DLM timeout while clean (blocking acquire failure inside handoff) → its own error per cluster policy; fatal signal → do NOT casually add EINTR.
- B completeness conditions: retry only with clean trans; AG registrations drained; no joined-inode leak across retries; per-node randomized backoff (deterministic re-synchronizes 32 nodes); cap backoff; no counter overflow; distinguish op retry from cluster failure (else genuine DLM death = infinite hang); audit no namespace side effects before retry point.
- Long-term bounded-progress shape (optional, only if starvation bound becomes a product requirement): fair admission token ordered BEFORE all entry ILOCKs (namespace-level, never needed by BAST/AIL/fence/recovery); coverage must be complete across rename/remove/create/link. DLM-level ticket that blocks peers = same I2 inversion, don't.

## Implementation notes (this session)
- xfs_rename (xfs_inode.c ~6486): drop `preacq_tries <= 3` bound + drop EAGAIN→ETIMEDOUT; add shutdown check per retry; cap jitter multiplier; P290-RENAME-CLEANRETRY probe added.
- xfs_remove (xfs_inode.c ~5950, p13_tries): same shape, same treatment.
- Watchdog msleep→condvar (disklock.c:822) fixed same session (precond D-state artifact).

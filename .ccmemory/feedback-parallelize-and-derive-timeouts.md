---
name: feedback-parallelize-and-derive-timeouts
description: User (sess17): NEVER reuse a prior session's timeout — derive each one (RULE 0). Per-node/cluster chores MUST run in parallel (shell & or subagents),…
metadata:
  type: feedback
tags: [timeouts, parallelism, rule0]
---

# Derive every timeout; parallelize every per-node chore

**User feedback, 2026-06-10 (sess17), angry, after I reused a 590s timeout
for cluster_reset_n.sh:**

> "a _10_ minute timeout to reset the cluster? are you kidding me? ... why are
> you not having subagents do this crap? ... You better be doing them in
> parallel. I'm not kidding."

**Why:** RULE 0 already requires deriving budgets from measured operation
time; copying a previous session's round number is the exact violation it
names. And serial 16-node loops (ssh per node, dmesg harvest per node,
verify per node) waste 16× wall clock for no reason.

**How to apply:**
- Before ANY timed command: write the budget = measured infra + 2× native
  workload. cluster_reset_n.sh 16 ≈ 180s ceiling (destroy/start ~5s parallel,
  boot-to-ssh ~40s, prep ~30-60s, verify ~10s parallel). Tighten after each
  healthy pass; record in tests/criteria/TIMEOUT_BUDGETS.md.
- Any loop over test nodes runs backgrounded subshells + wait (the pattern
  already in cluster_reset_n.sh). Audit any script before running it: if it
  has a serial per-node loop, parallelize it first.
- Independent diagnostics/harvest/analysis tasks → run concurrently
  (parallel Bash calls in one message, background tasks, or subagents) —
  never one-after-another in the main thread.

Related: [[feedback_timing_is_first_class]], [[feedback_timing_is_failure]], [[never-reboot-clyde]]

---
name: ccloop-c7ee71c6-sess384-GPT-ruling-terminal-record-guarantee
description: sess384 RULE-5 ruling on D-374 NO_TERMINAL_RECORD: harness-side synthesized state is authoritative; node watchdog only enriches; kill tail -1 arbitra…
metadata:
  type: project
tags: [harness, run.sh, coord, rule6, defect-374]
---

## Context (sess384) — PROVEN mechanism for D-CRASH-CONSISTENCY-NO-TERMINAL-RECORD-CAPTURE-374

run.sh clamps the node-side rendezvous timeout `ct` to `tt-15` for
**dir_reuse_coherency only**. Every other criterion gets the global
`COORD_TIMEOUT=120`, which EXCEEDS its RULE-0 budget `tt` — rsync_paired 60,
crash_consistency 90, posix_multi 30, cache_coherency 60, zero_silent_loss 60,
scaling_curve/dlm_scaling/node_responsive 90, ... So the harness SIGKILLs the
ssh at the budget long before the node-side barrier can report BARRIER_TIMEOUT.

Corroboration: **BARRIER_TIMEOUT has never once appeared in criteria.json
history** — the state the code was written to report is structurally
unreachable. run.sh's own dir_reuse_coherency comment documents this exact
failure ("three straight wedged runs produced zero terminal records ... burned
a session chasing a silent wedge that the barrier layer had detected but was
never allowed to report") and the fix was never generalized.

What it masked (board 2026-08-20T20:33:36Z, rsync_paired FAIL 60s/60s
NO_TERMINAL_RECORD=32): test1 printed NOTHING in 60s (stalled inside the
workload, NOT at a barrier); test2 and test4 `files=0/400 rc=23`. Real faults,
none of it on the board.

## The ruling (gpt-5.6-sol) — implement in THIS order

1. **Harness-side synthesized terminal state is AUTHORITATIVE.** Capture each
   `timeout ssh` exit status (the current `| grep -v` pipeline DISCARDS it) and
   when no RESULT line exists synthesize: rc 124/137 -> BUDGET_EXHAUSTED,
   rc 255 -> TRANSPORT_ERROR, else MISSING_TERMINAL_RECORD (remote_exit=N).
   No node-side mechanism can guarantee delivery before an external SIGKILL.
2. **Generalize the ct clamp** with a per-node HARD deadline (when timeout
   fires) and a REPORTING deadline (hard - reserve). Barriers cap at
   min(COORD_TIMEOUT, reporting_deadline - now); the poll interval itself must
   also be capped or a 2s poll overruns a 1s effective timeout.
3. **Audit every barrier call site** — returning 1 only helps if the caller
   converts it into finish_state BARRIER_TIMEOUT. Watch for ignored returns,
   set -e, barriers in subshells, traps that overwrite the state.
4. **Atomic breadcrumbs + counter snapshot.** `echo > file` has a real
   O_TRUNC-then-write race; use write-to-tmp + `mv -f` on the same fs. The
   watchdog CANNOT read live shell vars (fork-time copy), so ck/ckeq/step must
   maintain the snapshot file.
5. **Node watchdog is best-effort enrichment, never the guarantee.** Start it
   from an explicit idempotent init call, not as a source-time side effect.
   Use $BASHPID (not $$) for the main-shell pid. Killing the bash pid does NOT
   kill a stuck rsync child, and a D-state task cannot take a signal at all —
   only a pre-created cgroup/setsid group makes termination reliable; blind
   `kill -- -$pgid` can hit unintended processes.
6. **Replace `tail -1` arbitration with explicit source precedence:**
   test result > watchdog fallback > harness fallback. Otherwise a late
   BUDGET_EXHAUSTED hides an earlier, more specific SYSCALL_HANG. Tag records
   with src=test|watchdog|harness and select by source, not line position.
7. **Keep heavy forensics OUT of the RESULT line** (kernel stacks, dmesg): they
   burn the reserve, can block, and can malform the protocol record. Emit the
   one-line record FIRST, then bounded best-effort forensics to /dev/kmsg or a
   node-local artifact. Observed ssh block-buffering LOSES unflushed stdout when
   the kill lands, so a node-local terminal spool the harness fetches after the
   timeout is a valuable third delivery path (live stdout / spool / synthesized).

## Deadline arithmetic
- Use MILLISECONDS. Whole-second rounding plus launch skew eats a 30s budget's
  reserve.
- Compute the deadline per node immediately before that node's `timeout` starts
  (each node has its own timeout instance), so ssh connect latency is correctly
  charged against the budget.
- Convert the absolute deadline to a RELATIVE remaining interval once at node
  startup, then use relative sleeps — an NTP step mid-test otherwise moves the
  watchdog. Keep the absolute value for logging.
- If less than the reserve remains when the script starts, emit
  BUDGET_EXHAUSTED reason=insufficient_time_after_ssh_connect immediately
  instead of starting the workload.
- Reserve must exceed max clock offset + barrier poll granularity + scheduling
  delay + write/flush time. Pick 3-5s fixed for short criteria, empirically.

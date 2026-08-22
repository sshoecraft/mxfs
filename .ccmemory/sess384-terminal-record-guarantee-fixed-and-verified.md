---
name: sess384-terminal-record-guarantee-fixed-and-verified
description: sess384: D-374 NO_TERMINAL_RECORD FIXED AND VERIFIED on 0.19.7 — three-path terminal-record guarantee, full 32/caw board green, cause exercised 3x.
metadata:
  type: project
tags: [harness, run.sh, coord, rule6, defect-374, 32caw, fixed]
---

## D-CRASH-CONSISTENCY-NO-TERMINAL-RECORD-CAPTURE-374 — CLOSED, sess384, 0.19.7

Ledger open count 52 -> 51.

### Cause (proven, both prior arms were wrong)

`run.sh` clamped the node-side rendezvous cap to the criterion's kill box for
**dir_reuse_coherency only**. On the other 26 applicable rows `COORD_TIMEOUT`
(120s) EXCEEDED the RULE-0 budget, so a stalled rendezvous was SIGKILLed before
the barrier layer could report it. The dispatch also piped ssh into `grep -v`,
discarding `timeout`'s exit status.

**The tell: `BARRIER_TIMEOUT` had never appeared once in criteria.json's whole
recorded history.** When a state the code is written to emit has literally never
been observed, the path is unreachable, not merely unused. That single query
settled a defect two prior sessions had chased as a "capture race".

### Fix (3 delivery paths, source precedence, nothing widened)

1. `src=test` — the test's own finish/finish_state
2. `src=watchdog` — node-side, at the reporting deadline (breadcrumb names the step)
3. `src=harness` — synthesized from `timeout`'s rc (124/137 BUDGET_EXHAUSTED,
   255 TRANSPORT_ERROR, else MISSING_TERMINAL_RECORD). Runs outside ssh, cannot fail.

Plus a universal deadline clamp in `coord_eff_timeout()`, a node-local spool the
harness fetches before synthesizing, and a `steps[...]` census in `measured`
because `fail_reason` is capped at 400 chars (≈6 of 32 nodes).

### Verification

- `tests/d384_terminal_record_guarantee.sh` 13/13 (node mechanics, single host, ~25s)
- Cause exercised at 32 nodes twice via `MXFS_STALL_RANK`/`MXFS_STALL_S`:
  `states:BUDGET_EXHAUSTED=32 ... steps[injected-stall=1,pm barrier clean=31]`
- Exercised once by a NATURAL failure: a real rsync_paired collapse reported
  `states:BUDGET_EXHAUSTED=9,FAIL=23 ... faildist[0x9,1x15,4x8] steps[rsync barrier ready=9]`
  — 23 real per-node verdicts where there used to be none
- FULL 32/caw board after the change: **24 PASS, 3 FLAKY(passing), 0 FAIL**,
  walls at or better than before (cache_coherency 24s vs 33s despite 654
  breadcrumb writes; crash_consistency 83s vs 84s; dir_reuse 107s vs 101s).
  The fault/destructive class — most exposed to the clamp — is green.

### Two design points that are easy to get wrong

- The watchdog **polls** for the main shell instead of sleeping the interval: a
  background subshell inherits stdout and holds the ssh pipe open, so a one-shot
  sleep stretches every passing test to its full budget whenever the test exits
  without reaching `finish()` (several set their own EXIT trap).
- Liveness is `(pid, starttime)` from `/proc/<pid>/stat`, not `kill -0` — a bare
  pid check is the PID-reuse TOCTOU that once wedged every barrier criterion.

### What it immediately bought

The first natural failure it captured produced the errno that
`D-RSYNC-OVERWRITE-LAP-USERSPACE-FAIL-ERRNO-UNKNOWN` had been open on since
sess212: **EBADE(52)** from `mkstemp`, i.e. a raw SCSI RESERVATION CONFLICT
leaked to userspace, followed by EIO(5) once the mount finished shutting down.

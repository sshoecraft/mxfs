---
name: trap-a-silent-instrument-and-a-clean-system-are-the-same-observation
description: TRAP (sess571): a probe that logs only on the failing path makes "no failure" and "never reached" identical; always prove the instrument can fire.
metadata:
  type: feedback
tags: [rule4, instrumentation, d0945, d0946, positive-control]
---

# A silent instrument and a clean system are the same observation

This bit twice in one session, one layer apart, and both times the silence
looked like good news.

## Instance 1 — the gate that only logs when it refuses

`v5_tcp_release_gate()` prints `P-TCP-RELEASE-POISONED` **only on refusal**. So
with the gate disabled the log says nothing at all, and

- "the gate did not refuse" and
- "no inode was ever freed on this path"

are the same observation. That is why D-0945 was reasoned about for a whole
session without ever being reproduced on demand — every run was consistent with
both the defect and the absence of the opportunity.

**Fix:** a probe that fires on BOTH arms of the knob —
`P945-INO-FREE-RELEASE ino=N poisoned=1 gated=0|1`. The failing arm now PRINTS
its own failure, and a lap that never took the route reports "not exercised"
instead of scoring clean. It fired on 2 of 6 laps, so 4 of 6 would otherwise
have been silently miscounted as evidence of correctness.

## Instance 2 — the choke-point census that came back zero

`P945-RELEASE-WHILE-POISONED` (0.75.115) was added at
`mxfs_dlm_unlock_gen` / `mxfs_dlm_send_unconditional_release` to name any
release that runs while the session is poisoned. Ten death laps → **zero lines**.

Tempting reading: "every release path is gated, class closed." Actual status:
unknown, because a dead probe returns zero too — a wrong `cb_data`, an
unregistered callback, a registration on a branch this configuration doesn't
take, all produce a confident, clean-looking zero.

**Fix:** `tests/d0945_chokepoint_positive_control.sh` uses an existing 0644 knob
as the control. `poison_gate_ino_free=1` → the wrapper returns before the
primitive, so the choke point *should* be silent. `=0` → the same free falls
through into the primitive while poisoned, so it *must* fire. Both directions
have a defined right answer; that is what makes it a control rather than one
more measurement.

## The rule

**Before a zero count becomes evidence, prove the instrument can produce a
non-zero one.** Preferably with a knob the tree already has, in the same run, so
the positive and negative arms share every other condition.

RULE 10 already says a disposition-critical NEGATIVE from a subagent is never
evidence and must be re-run in the parent. This is the same hazard one level
deeper: the negative can be false in the *kernel*, not just in the reporting.

## Related shapes seen the same session

- `agmeta_shutdown_retire.sh` scored the injected death by grepping the
  log-error text, so a shutdown by a DIFFERENT route scored as "no shutdown" —
  a vacuity, not a finding. It buried a critical defect (D-0946) for a session.
  Assert on the unexpected route explicitly.
- Counting from `tests/evidence/<lap>/*.txt` gave 16 ATOMIC-SKIPs for an arm the
  driver scored 0: those files are `dmesg` TAILS carrying earlier laps and
  boots. An evidence file named after a lap is not windowed to that lap.

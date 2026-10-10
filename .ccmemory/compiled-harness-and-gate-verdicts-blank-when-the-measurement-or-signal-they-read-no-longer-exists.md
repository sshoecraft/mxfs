---
name: compiled-harness-and-gate-verdicts-blank-when-the-measurement-or-signal-they-read-no-longer-exists
description: Harness assertions fail from empty captures after a fix shortens a state or a design change removes it; a sentinel-filtering gate opens on a delibera…
metadata:
  type: feedback
tags: [compiled, harness, measurement-integrity, dlm, settle-gate]
---

Three traps share one shape: a verdict whose input is empty or filtered is read as a verdict about MXFS (or as "nobody objected"), when it only says the measurement or signal is absent.

## 1. Periodic capture vs. a fix that shortens the state

[[trap-an-assertion-reading-a-periodic-capture-fails-when-a-fix-ends-the-state-faster-than-the-sampling-cadence]]

- `tcp_lockreq_blackhole.sh` asserts which call site was blocked by grepping the blocked task's kernel stack from `w_samples.txt`, written by a sampler on a 60 s cadence. A new lease-closure arm ended the wait 3 s after closure; the sampler never ran while the task existed, the file had no stack, and four descriptive assertions failed (`FAIL the blocked task was in an inode acquire got=0 want=1`) while every substantive assertion passed.
- Symptom: substantive assertions pass, descriptive ones ("blocked in X", "counter non-zero at the time") fail together, all reading one file.
- Fix: take a one-shot capture at the moment the state is known to exist (the pre-close probe already proves the waiter was blocked), and select the capture per arm: periodic file for long-lived states, one-shot for short ones. Deepen the one-shot capture to match the sampler (`head -20`, not `head -12`) or frames the assertions grep for are lost.
- When a new arm makes an assertion inapplicable, split it by cause and give the arm its own replacement (the withdrawn-mount arm asserts the filesystem was shut down by the closure and W did not read stale bytes). Removing an assertion without a replacement is relaxing it.

## 2. Assertion written before a design ruling

[[trap-a-harness-assertion-written-before-a-design-ruling-fails-from-a-measurement-that-no-longer-exists]]

- `tests/dlm_wait_signal.sh` asserted "reader did not spin (max stime < 100 ticks)" and printed `max_stime_ticks=none ... FAIL` on a healthy lap. The 0.82 remote-acquire abandonment protocol (D-0958) makes a killed task abandon its lock wait at once, so every sample was `gone=1`: no live process to sample. The harness turned the absence of a measurement into a FAIL.
- Second trap in the fix: requiring `P958-ACQ-CANCEL-ACK` failed the next lap, because an inode the reader masters itself is abandoned locally and sends no CANCEL. Require the abandonment line, and that every CANCEL sent was acked.
- Rule: when a healthy lap FAILs after a design change, first check the assertion still measures anything. A verdict over an empty input (`none`, an absent process, a count over nothing) must ABORT ("nothing measured") or be re-derived from the current design. Put the vacuity check in the harness (`timeout_rc=124` proves the signal reached a live reader).

## 3. Fail-closed gate open to a deliberate sentinel

[[trap-a-gate-fail-closed-against-a-different-report-is-open-to-no-report-and-a-zero-is-a-report]]

- The 0.83.4 joiner settle gate refused after its 20 s window only if a live member beaconed a different view. An incumbent mid-prepare beaconed view `{0,0}` ("I have installed no multi-node view", i.e. "you are not admitted") and two filters dropped it as "no report" (`lease.c` forwarded only a non-zero hash; `mxfs_dlm_report_peer_view` returned on hash 0). The gate opened unconfirmed (`P-D7-SETTLEGATE waited=18000ms confirmed=0`); every joiner acquire was then DEFERred until budget or the 30 s watchdog refused the mount.
- Pattern: a sentinel (0, empty, unknown) that the sender emits deliberately is data. Audit every filter between sender and predicate for a sentinel drop before trusting a "nobody objected" gate.
- The FREEZE_REQ DEFER is a plain park on the requester at 100 ms cadence with no progress relayed; it is a safety net, not a wait.

## Common checklist

- Before reading a failed assertion as an MXFS defect, confirm its input existed: sampler overlapped the state, process was alive, count was over something.
- Empty input is ABORT, never PASS or FAIL.
- Never relax or delete an assertion a design change invalidated; split by cause and replace it.

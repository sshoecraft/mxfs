---
name: trap-an-evidence-directory-named-ok-carries-the-manifest-label-not-a-verdict-and-in-flight-laps-at-a-session-end-are-not-results
description: TRAP (s65): tests/evidence dirs ending in "-ok" are the capture-gate label (harness name + "-ok" arm), not a PASS; the s62e "long healthy laps in fli…
metadata:
  type: feedback
tags: [evidence, harness, capture-gate, verification]
---

# "-ok" in an evidence directory name is a label, and "in flight" is not a result

## What bit
D-A-HARNESS-CAN-MEASURE-THE-WRONG-DEVICE's next step (written at the end of s62) said: "Long healthy laps s62e in flight (d0932 x4, sole_survivor x2, recov_bmbt_reuse, d0356, depart_takeover, join_during_takeover)". The evidence listing at the start of s65 showed directories such as `20260919T040458Z_d0932_s62e-d0932_fence_takeover_probe-ok` and `..._solesurv_s62e-sole_survivor_restart-ok`, and a scout reported them as "ends in -ok".

They were not OK. The suffix is the capture-gate label (`<label>-<harness>-ok` is the healthy arm of tests/capture_fault_gate.sh; the fault arm is `-fault`). The verdicts, read from the gate's own log in the sibling `capture_gate_<label>` directory:
- d0932_fence_takeover_probe: `RESULT: FAIL ... stage=prep` — mkfs_mxfs returned 1 after "Zeroing disklock region"; the lap never ran.
- sole_survivor_gate_probe: `RESULT: FAIL fails=2 wall=322s` — "A issued no PREEMPT AND ABORT got=1" and "B completed its mount got=0" (MOUNT_RC=32 after 139 s).
- sole_survivor_restart: 12 lines, five PASS, no RESULT — killed with the session.
Only three of the ten "in flight" laps had even started.

## The lesson
- A verdict lives in a `RESULT:`/`VERDICT` line, and only there. Never read one from a directory name, a label, or a record's "in flight".
- A record's next-step written while laps are running is a promise. The session that inherits it must go to the gate logs (`tests/evidence/gate_<label>/<harness>.log` or `capture_gate_<label>/*.log`) before crediting anything, and the session that writes it should say "launched, unverified", never "in flight" as if that were progress.
- The sweep driver for these is `tests/capture_gate_sweep.sh ensure|lap <label> <harness>` with bounds from `tests/capture_gate.manifest` (healthy column); laps over 570 s need nohup + `timeout 590 tail --pid` waits, one Bash call each.

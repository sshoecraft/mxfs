---
name: compiled-defect-disposition-and-harness-prediction-traps-next-step-text-target-class-and-evidence-labels
description: Do not dispose a defect on its own next-step text, predict PR keys without the target class, or read a verdict from an -ok dir name or in-flight lap.
metadata:
  type: feedback
tags: [compiled, defects, fencing, harness, evidence, scsi-pr]
---

# Dispositions and harness predictions must come from the ruling, the target class and the verdict line

Three traps from the fence crash-matrix and capture-gate work share one failure mode: a session accepted a convenient proxy (a prior session's text, a harness default, a directory name) in place of the authoritative source.

## 1. A record's next-step is not the disposition standard; the banked ruling is
`D-FENCE-CRASH-MATRIX-UNTESTED` next-step (s73) said closure = both arms' six cuts measured. The next session was about to remove the record on the silent-victim sweep's 6/6 PASS. `docs/rulings/fence-crash-matrix-cuts.md` (s68) says cuts 1-6 are a first tranche, never closure, and lists the missing crash points (in-flight P&A variants, partial snapshot/seal, partial replay, non-durable stage advances, lost-ack zero, competing owners, partition/reconnect, APTPL target restart); the s72 silent-arm ruling extends it and replaces nothing. Removing on the next-step text would redefine the requirement after the measurement.
- Before `defects.py remove`, read every `docs/rulings/*.md` the record's found/evidence cites and check the closure claim against the ruling's own "what counts as closure" sentence.
- A next-step is the previous lap's plan; it inherits nothing from the ruling. Outcome: record updated (12/12 recorded, remaining matrix restated from the ruling), not removed.
- Source: [[trap-a-closure-condition-written-into-a-records-next-step-can-contradict-the-banked-ruling-read-the-ruling-before-disposing]]

## 2. A crash-cut harness must know the target's registration-persistence class
Sweep s71a (2/tcp, qnap LUN) failed cuts 1 and 2 on "victim key still registered got=0 want=1". Captures disproved the prediction, not MXFS: K0 both keys, K1 only the prover's (no PROUT issued), K2 zero keys with no MXFS instance alive. The QNAP drops a registration when the I_T nexus dies (already measured 2026-09-04 by `tests/pr_session_drop_probe.sh`: key gone, PR generation unchanged). The s70 harness carried an SCST/LIO-class expectation that a dead initiator's key persists.
- Cuts 1-3: assert "PR generation unchanged between K0 and K1" for every class; key presence follows the class.
- Cut 4 is reached via the sole-survivor gate (kind 20), not a P&A that consumed the key; cuts 5/6 certificates name EXCLUSIVE_WRITE_GATE. A destroyed victim's successor proves itself by boot succession; a lone successor of a destroyed prover by the gate.
- The ruling already said a registration-deleting target is not a boot boundary and to verify independently that P&A consumed the intended registration. Read the rig's target class (probe evidence, rig declaration) before writing any PR-state prediction.
- Source: [[trap-a-crash-cut-prediction-of-a-registered-victim-key-is-written-for-a-persistent-target-and-the-qnap-purges-the-key-with-the-session]]

## 3. An "-ok" evidence directory is a label, and "in flight" is not a result
`D-A-HARNESS-CAN-MEASURE-THE-WRONG-DEVICE`'s next-step (end of s62) claimed long healthy laps were in flight; s65's listing showed dirs ending `-ok` and a scout reported them as passing. The suffix is the capture-gate arm label (`-ok` healthy arm, `-fault` fault arm) from `tests/capture_fault_gate.sh`. Actual verdicts from the sibling `capture_gate_<label>` logs: d0932_fence_takeover_probe `RESULT: FAIL stage=prep` (mkfs_mxfs rc 1, lap never ran); sole_survivor_gate_probe `RESULT: FAIL fails=2 wall=322s` (no PREEMPT AND ABORT; B mount rc 32 after 139 s); sole_survivor_restart killed with the session, no RESULT. Only 3 of 10 laps had started.
- A verdict lives only in a `RESULT:`/`VERDICT` line, never in a directory name, label or "in flight".
- A next-step written while laps run is a promise: write "launched, unverified". The inheriting session reads `tests/evidence/gate_<label>/<harness>.log` or `capture_gate_<label>/*.log` before crediting anything.
- Driver: `tests/capture_gate_sweep.sh ensure|lap <label> <harness>`, bounds from `tests/capture_gate.manifest` healthy column; laps over 570 s need nohup plus `timeout 590 tail --pid` waits, one Bash call each.
- Source: [[trap-an-evidence-directory-named-ok-carries-the-manifest-label-not-a-verdict-and-in-flight-laps-at-a-session-end-are-not-results]]

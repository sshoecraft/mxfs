---
name: trap-a-crash-cut-prediction-of-a-registered-victim-key-is-written-for-a-persistent-target-and-the-qnap-purges-the-key-with-the-session
description: TRAP (s71a, D-FENCE-CRASH-MATRIX-UNTESTED): fence_crash_cuts predicted "victim key still registered" at cuts 1-3 and PREEMPT_ABORT_DONE at 5/6; the q…
metadata:
  type: feedback
tags: [fencing, scsi-pr, harness, qnap, crash-cuts]
---

# A crash-cut harness must know the target's registration-persistence class before it predicts a key

Sweep s71a (0.89.8, 2/tcp on the qnap LUN) failed cuts 1 and 2 on exactly one
assertion each: "cut N: B1's key still registered at the cut got=0 want=1".
The harness's own captures disproved the prediction, not MXFS:

- K0 (READ KEYS from the prover before the arm): both keys registered.
- K1 (from the prover, parked at cut 1 BEFORE fence_intent, victim destroyed):
  only the prover's key.  Nothing had issued a PROUT.
- K2 (from the victim host's fresh boot, prover destroyed too, no MXFS
  instance alive anywhere): zero keys.

So the target removes a registration when its I_T nexus dies.  That was
already measured on 2026-09-04 (tests/pr_session_drop_probe.sh: key gone,
PR generation unchanged) and the module was designed around it (fence kinds
BOOT_SUCCESSION_ABSENT and EXCLUSIVE_WRITE_GATE, scsipr.h names the QNAP
TS-453 Pro).  The harness written in s70 carried the SCST/LIO-class
expectation that a dead initiator's key stays as the fence target.

What follows on a purging target:
- cuts 1-3: the victim key is ABSENT at the cut; the honest assertion for
  every target class is "PR generation unchanged between K0 and K1" (no PROUT
  left), with key presence following the class.
- cut 4 is reached through the sole-survivor gate (kind 20), never through a
  P&A that consumed the key; cuts 5/6 certificates name EXCLUSIVE_WRITE_GATE.
- the successor of a destroyed victim proves it by boot succession; the
  successor of a destroyed prover, when alone, by the gate.

The design ruling (docs/rulings/fence-crash-matrix-cuts.md) already said "a
target that deletes registrations on disconnect is not a boot boundary" and
"verify independently that the P&A consumed the intended registration, never
infer it from the cut number".  Read the rig's target class (the probe's
evidence, the rig declaration) before writing a PR-state prediction.

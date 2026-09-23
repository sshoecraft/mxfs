---
name: technique-the-fence-matrix-splits-into-crash-cuts-and-lost-evidence-and-they-are-not-the-same-entry
description: TECHNIQUE (s74, D-FENCE-CRASH-MATRIX-UNTESTED): a crash cut kills the prover; the lost-response entry keeps it ALIVE with real P&A effects and no pro…
metadata:
  type: feedback
tags: [fencing, scsipr, injection, design]
---

# Crash cut vs lost evidence — two different entries, one easy to mistake for the other

`tests/fence_crash_cuts.sh` cut 4 parks the prover after the PREEMPT AND ABORT
proved exclusion and destroys the VM there. The proof dies *with* the prover and
a successor recovers across a boot boundary. That is banked, 12/12 on both
victim arms.

It establishes nothing about a prover that is **still alive and still
deciding**. That is a separate matrix entry (session-74 ruling, banked in
`docs/rulings/fence-lost-response-live-prover.md`):

- the target really performs the P&A — registration removed, task set aborted;
- only the RESULT is lost, at the fencing consumer boundary;
- the prover keeps running, with a durable `MAY_HAVE_RUN` arm and no proof.

The defect it hunts is the shortcut out of that state: turning the victim key's
now-absence into evidence that the unanswered command succeeded, or into
`BOOT_SUCCESSION_ABSENT` with no boot boundary.

## Where the injection has to sit, and why

`pal/linux/kern.c`, inside `mxfs_pal_prout_preempt_abort`, **after**
`scsi_execute_cmd` returns and **before** that function's own status
normalization and `P302-PROUT-ABORT-FAIL` reporting.

- Injecting *before* submission, or dropping the command, tests "the command
  never ran" — which the endpoint cuts already cover, and which is strictly
  weaker.
- Injecting *after* the reporting block returns the right value to the caller
  but omits the log line a real lost response emits. That is an observable
  difference between the injected state and the state being modelled. (Caught
  by reading, after first writing it the wrong way.)

The substituted value is `-ETIMEDOUT` because that is what this stack's own
unanswered command yields; it reaches the fencing code as
`kind=ERROR, phase=MAY_HAVE_SUBMITTED` at `dlm/scsipr.c:2013`, which is the
tree's existing ambiguous representation. No new error class is invented to
reach a convenient branch.

## The retry latch is already in the tree

After the loss the prover re-drives, but it will **not** issue a second P&A: the
key is gone, so `fence_node` classifies `KEY_ABSENT_UNPROVEN` before the
submission boundary. The only mechanisms that can resolve the ambiguity are the
sole-survivor exclusive-write gate and boot succession, and both already have
non-sleeping refusal knobs (`fence_gate_inject_refuse`,
`fence_bootsucc_inject_refuse`). Hold them for the observation, release them as
the recovery stimulus. Do not build a blocking hold: the prover runs on the
disklock heartbeat thread, and a prover that went stale because the harness
parked its heartbeat is a different lap.

## The verdict must be two-part

"Certificate or a named block" passes an implementation that always blocks.
Required: (A) with the alternatives refused, nothing certified/sealed/claimed/
replayed/zeroed and the durable arm intact, with the error path shown to have
actually run; then (B) with them released, a real certificate naming the
mechanism **actually used** and a completed recovery, bounded. Blocking past
the point where a valid proof opportunity exists is a liveness failure.

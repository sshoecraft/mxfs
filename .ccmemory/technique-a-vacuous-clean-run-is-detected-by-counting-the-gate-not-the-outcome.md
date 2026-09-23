---
name: technique-a-vacuous-clean-run-is-detected-by-counting-the-gate-not-the-outcome
description: TECHNIQUE (sess572): 16 rounds of a D-0946 harness scored 0 hits and read as clean; they had never reached the code under test. Count the gate's own…
metadata:
  type: project
tags: [measurement, vacuity, harness, d0946]
---

# Score the gate, not only the outcome

## The observation

`tests/d0946_disklive_knob_vs_aging.sh` ran 8 rounds in `peer` mode and 8 in
`local` mode on 0.75.116 and scored `DISKLIVE=0 DEFERLIVE=0` in 16 of 16. Read
as a result, that says the defect did not reproduce. It said nothing of the
kind: the same rounds scored **zero** `P-FREEOB-CHAIN-LIVE` and **zero**
`P946-VALIDATE-ALLOW`, so the arm of the validator that carries the defect never
ran once. The rounds were vacuous, and a vacuous round and a clean round print
identically if you only count the failure.

## Two harness properties were closing the window

1. **`sync -f` between the create pass and the delete pass.** The defect lives
   in the gap between a free committing in core and its dinode reaching the
   platter. A sync publishes every owed free, so by the time the next round
   re-allocated the number there was nothing pending. Removing every sync and
   interleaving free-then-create one inode at a time made the gate fire 40 times
   in 6 rounds.

2. **Zero-length files.** The failing path is entered only when the in-core
   shell satisfies `i_mode != 0 || i_nblocks != 0` (xfs_icache.c's deferred
   deadshell classification); the captured failure's shell was `mode=00 nblk=11`.
   `: > f` leaves both zero, so even with the sync removed the create could not
   reach the recycle gate. The failing workload's file was `fallocate -l 8M`.

## The rule this produced

Every round of a defect harness reports a **gate-fire count** alongside its
outcome, and the summary refuses to call a zero-outcome run "not reproduced"
when the gate-fire total is zero — it calls it VACUOUS. Concretely:

    PUBPEND=n PUBALLOW=n DRIVEOK=n DRIVETO=n PSTORM=n CHAINLIVE=n DEADSHELL=n

    READ: VACUOUS — the pubob arm never fired in N rounds, so a clean result
          here is indistinguishable from an instrument that cannot fire.

## A second trap inside the instrument itself

Both arms of the A/B first shared one `static atomic_t` for their rate limit.
The fix arm burned all 32 slots in round 1, and the control arm then printed
nothing for the rest of the run — reading as "the control arm never fired" when
it was firing constantly (its `CHAINLIVE` count, 201 in one round, gave it
away). **One rate-limit counter per arm**, or the louder arm silences the other
and the A/B is reported backwards.

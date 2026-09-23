---
name: design-fence-outcome-legs-are-precommand-retryable-ambiguous-terminal-and-the-third-operation-is-proof-resume
description: DESIGN (Astra s74 ruling): ordinary retry, proof resume and takeover are three DIFFERENT operations; a live prover needs proof-resume for its own att…
metadata:
  type: project
tags: [fencing, scsipr, design, ruling, recovery]
---

# Three operations, not two — and the sole-survivor gate is not a free pass

Design-consult ruling (Astra, session 74) on fixing
D-FENCE-POSTSUBMIT-AMBIGUITY-NO-RECONCILIATION-381, after the lost-response
entry measured it live on 2/tcp.

| Operation | Meaning |
|---|---|
| Ordinary retry | Re-enter the victim-key fencing operation after `PRECOMMAND` |
| **Proof resume** | Advance an unresolved attempt using independently sufficient evidence or a fresh fencing operation |
| Takeover | Change the OWNER of the durable recovery attempt |

The measured failure needs **proof resume by the same owner**. The tree has
only the other two, and the takeover sweep explicitly declines an attempt whose
holder is "our current incarnation" — so a live prover can never resume its
own unresolved attempt.

What must NOT be done to get there: broaden `mxfs_fence_attempt_is_retryable()`
to include `MAY_HAVE_SUBMITTED`; make
`mxfs_disklock_recovery_fence_retryable()` answer yes for a descriptor carrying
`MAY_HAVE_RUN`; weaken `v5_node_is_dead()` or the live-owner takeover check; or
route the continuation through a generic entry point that can fall through to
another victim-key P&A.

## The trap in "the gate doesn't name the victim key"

The sole-survivor exclusive-write gate issues `rk=own, sark=0, type=WE(1)`, so
it never names the victim key and cannot collide with an in-flight predecessor
*against that key*. That is **not** sufficient justification on its own:

1. The original P&A removes the victim's registration.
2. Aborting the victim's already-accepted tasks may still be in progress.
3. The gate observes the key absent and completes, post-state `own_n==1`.
4. Recovery starts while an old victim write can still complete.

A second P&A operating on *currently registered* nexuses is not a drain of
tasks belonging to an **already-removed** registration. A host mutex around the
two calls does not order their execution at the target after a timeout. A late
*response* is harmless; a late *command execution* is not.

So the gate may supply the proof only once the outstanding-I/O / task-drain
obligation is closed — by an applicable target-enforced ordering/drain
guarantee with the right nexus, LU and multipath scope, or by showing all
unresolved predecessor effects are harmless. A coherent PR snapshot does not
repair the drain gap either.

Also: a zero-SARK P&A **is still a P&A** — count gate commands in the ambiguity
accounting, and give the gate its own durable command boundary, or a lost gate
response is simply a second ambiguity.

## Key still PRESENT

Key presence proves neither that the predecessor did not execute nor that it
cannot execute later, and no retry count or elapsed timeout converts it into
either fact. Correct behaviour: stay `FENCE_UNPROVEN`, do not enter the
absent-key branch, do not resubmit merely because time passed. The bound that
is legitimate is an **operational** one — after a finite window, get a valid
certificate or transition the local filesystem to an explicit failed/withdrawn
state. That deadline authorises loss of local service, **never a weaker
certificate**.

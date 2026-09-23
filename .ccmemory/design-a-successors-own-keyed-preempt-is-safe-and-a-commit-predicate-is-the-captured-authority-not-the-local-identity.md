---
name: design-a-successors-own-keyed-preempt-is-safe-and-a-commit-predicate-is-the-captured-authority-not-the-local-identity
description: DESIGN (Astra s81 ruling, D-381): the successor's second PREEMPT AND ABORT is disposed; a CAS validates an image you must first check against the cap…
metadata:
  type: project
tags: [fencing, design-ruling, persistent-reservations, recovery, admission]
---

# Three rulings that close out the ambiguity record's remaining items

Full text banked at `docs/rulings/fence-successor-command-and-commit-guards.md`.
This is the part a future session needs before touching these paths.

## The successor's second PREEMPT AND ABORT is DISPOSED

Not because anything prevents two commands being in flight — nothing does, and
nothing needs to.  With `rk=P sark=V` (dead predecessor) and `rk=S sark=V`
(successor), the target's PR **state-transition** order decides, not the order
responses arrive: whichever removes `V` first, the other finds no matching
service-action key and returns a non-success result that certifies nothing.
The late command cannot redirect its preemption to `S`, because it does not
name `S`.

The correct closure sentence: *the inherited submission marker is historical,
not a successor submission; the successor certifies only its own proof, never
the predecessor's unknown outcome and never registration absence.*

**Do NOT route an inherited `PRIOR_TERM_MAY_HAVE_RUN` to the read-only proof
path.**  That manufactures a lockout: victim still registered, predecessor
dead, no independent proof, and reads cannot make exclusion true.  Keep the
three operations distinct — takeover (new term, may issue its own command),
proof resume (same term, read-only), publication retry (publish what is
already held).

Two residuals survive and belong to the ambiguous-command item, not here:
**key reuse** (no live incarnation may acquire the old victim key while an old
operation naming it can still matter) and **error-handling escalation** (a
timed-out PR OUT whose EH submitted a LUN reset can abort the *successor's*
recovery I/O later — a term-scoped submission bit does not make that harmless).

## A CAS is not a commit predicate by itself

> CAS protects a validated expected image.  It does not validate that image
> for you.

The unsafe schedule: A resumes under term 7; B takes over at term 8; A enters
certify, reads **B's term-8 image** as its expected image, and CASes its
term-7 proof in.  The CAS succeeds and is perfectly correct — the missing step
was comparing the expected image against A's *captured* authority.

MXFS satisfies this today: `fauth` is issued once at
`mxfs_disklock_recovery_fence_intent` and carried unchanged to
`mxfs_disklock_recovery_fence_certify`, which re-reads the descriptor, runs
`recov_fence_auth_holds` against that captured token (`fence_term`, victim
node/incarnation, `recovery_gen`, owner and prover identity) and then CASes
against the validated image.  **Do not "simplify" this into a fresh
auth-issue before certify** — that is exactly the defect.

After a failed CAS, re-reading must not silently adopt a new owner or term:
reconcile an unknown publication outcome, never convert reconciliation into a
transfer of authority.

## "SEALED" is not a release condition for a rejoining node

A software admission barrier is a legitimate place to serialize a rejoin — you
cannot instruct the old unresponsive victim, but you can require a newly
starting successor to obey admission before any filesystem write.  What is
*not* legitimate is releasing on the seal by name.  If sealing only freezes the
list of the dead node's journal work: the successor mounts, modifies metadata
block M, and the survivor then replays the dead node's older update to M,
overwriting the newer state.

Release is correct only at recovery-complete, or once recovery locks and
exclusion are installed such that the joiner cannot touch conflicting metadata
or reuse the slice.  Measured window in this tree: `P236-FENCE-SEALED` to
`P163-RECOVERY-COMPLETE` is **~8.6 s** on the 2/tcp rig, and seal strictly
precedes replay dispatch (`v5_pr_fence_prove_locked` seals;
`v5_start_slice_recovery` dispatches afterwards from a separate caller).

Also: registration is not admission, but under a registrants-only or
all-registrants reservation a joiner's registration **does** confer
target-level write eligibility — so "the survivor holds the reservation" is not
available as a claim that the target excludes the joiner.  The sole-survivor
gate (single-holder WE, type 0x01) does exclude; boot succession certifies
under WE-AR (0x07) and does not.

## What a local timeout proves about a target command

Nothing.  A freed request, an EH return code or `DID_ABORT` is not target
quiescence; only a matched, target-confirmed task termination with the
transport's ordering guarantee is.  Even that is not rollback, does not prove
the original command returned GOOD, and does not retire the victim's writes.
There is **no honest fixed timeout** after which an unobservable target
operation becomes known dead — with neither termination evidence nor a
complete noninterference argument, stay blocked.  And a read-only resume must
never issue an abort or reset to manufacture its own evidence.

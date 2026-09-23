# The successor's second command, and the three guards a proof commit needs

Design-consult ruling (Astra, session 81) on the two items left open in
`D-FENCE-POSTSUBMIT-AMBIGUITY-NO-RECONCILIATION-381` after the publication
retry and the event-driven revisit landed.  It continues
`fence-ambiguous-drain-and-proof-resume.md`, whose two facts — a certificate
rests on ADMISSION *and* RETIREMENT, and the continuation is a third operation
distinct from retry and from takeover — are unchanged and assumed here.

The ruling is about code and protocol.  It is not a measurement of the QNAP,
and nothing in it may be read as one.

---

## Part 1 — the successor's second PREEMPT AND ABORT is DISPOSED

The allegation was: a successor to a prover that died mid-ambiguity takes the
attempt lease over and issues a fresh PREEMPT AND ABORT while the
predecessor's may still be in flight.

**It is disposed as a design defect** — but not for the reason that looked
obvious.  The closure is *not* "the term-scoped marker prevents concurrent
commands."  It does not serialize them and does not need to.  The closure is:

> The inherited submission marker is historical, not a successor submission.
> The successor may submit its own keyed exclusion operation.  Its certificate
> rests on its own proof, never on the predecessor's unknown outcome and never
> on registration absence.  Overlapping operations against the same frozen
> victim key do not themselves allow the predecessor to preempt the successor.

### The two orders, and why neither is damaging

With `P` the predecessor's key, `S` the successor's, `V` the frozen victim key,
the commands are `rk=P sark=V` and `rk=S sark=V`.  What matters is the target's
PR state-transition order, **not** the order responses arrive in.

| first effective transition | the later command | consequence |
|---|---|---|
| predecessor removes `V` | successor finds no matching `V` | a non-success result; no certificate comes from that command |
| successor removes `V` | predecessor finds no matching `V` | it cannot redirect its preemption to `S` — it does not name `S` |

In the first row the predecessor may still be completing its abort work while
the successor already sees a conflict.  **That is exactly why a conflict, or
key absence, may never become a retirement witness** — which is what the
prior-term history bit preserves.

This holds only while all of the following are true, and each is a live
obligation rather than a footnote: the keys are distinct and non-zero with
ordinary matching-key semantics (not a zero-`sark` all-registrants operation);
the target serializes PR state transitions correctly; nobody restores a
registration under `V` during the sequence; the successor certifies only its
own qualifying result or a separately valid proof route; and the command route
supplies both the admission and the retirement fact — receiving a response, or
observing registration absence, is not enough.

### Do NOT route an inherited ambiguity to the read-only path

Sending a successor that inherits the prior-term marker down the read-only
proof route instead of the command route **manufactures the liveness failure**
the whole continuation exists to avoid: the victim is still registered, the
predecessor is dead, no boot succession or other independent proof exists, the
successor is forbidden the one command that could establish exclusion, and
repeated reads cannot make exclusion true.

The three operations stay distinct:

- **takeover** — new owner and new term, eligible to perform its own
  authorized command;
- **proof resume** — same owner, same term, read-only, no fresh fencing
  command;
- **publication retry** — publish or reconcile the proof already held, without
  re-proving it.

### One obligation the disposal leaves behind

The takeover path ignores the return of its prove call and then claims the
recovery lease.  That is only harmless while claiming a lease **cannot**
authorize replay without the mandatory certificate gate.  That is a property to
check, not to assume.

### Two residuals that are NOT second-command defects

They belong to Part 2(c) and must not be repaired by disabling takeover.

**Key reuse.**  A real damaging schedule exists if the victim key can come
back: the predecessor's `P→V` command is still pending before its effective
transition; the successor's `S→V` succeeds; recovery proceeds; a live
incarnation registers under `V` again; the predecessor's command finally
executes while its own `P` registration is still valid, removing that live
registration and aborting its tasks.  Per-incarnation derivation prevents this
only if it delivers actual non-reuse over the lifetime of outstanding commands
and surviving target registrations.  The property required is:

> no live incarnation can acquire the old victim key while an old operation
> naming that key can still matter.

Reusing the old victim's target-visible I_T nexus deserves separate treatment:
a command that has not yet selected a registration and one already carrying out
abort work against a selected nexus are different states, and a new key alone
is not evidence that task-management work on that nexus has finished.

**Error handling has a broader scope than the command it was recovering.**
The predecessor's PR OUT times out; its SCSI error handling submits a LUN reset
or another broader-scope recovery operation; the predecessor dies with that
unresolved; the successor completes its own PREEMPT AND ABORT and starts
recovery; the outstanding reset executes and aborts the successor's recovery
I/O.  A term-scoped submission bit does not make that reset harmless.

Unit attentions and the PR generation are not retirement witnesses either, and
the generation must not be treated as an unbounded non-wrapping operation id.

---

## Part 2(a) — the commit predicate

A bytewise atomic descriptor CAS **is** a conjunction of equality predicates
over the compared fields; no separate hardware predicate for the owner epoch or
the term is needed.  But:

> CAS protects a validated expected image.  It does not validate that image for
> you.

The authority captured when the proof was acquired or resumed must be carried
to the commit, and the expected image checked against **it** — not merely
against the local node's identity.  The unsafe schedule a bare CAS permits:

```
A dispatches resume under term 7.
B takes the attempt over and installs term 8.
A enters certify(), reads B's term-8 descriptor as its expected image.
A publishes its term-7 proof with CAS(expected_term_8 -> certificate).
The CAS succeeds.
```

The CAS behaved perfectly.  The missing step was comparing the expected image
against A's captured term-7 authority.  Done correctly, the same CAS *is* the
atomic ownership guard:

```
A validates the expected image: owner A, term 7.
B changes it to owner B, term 8.
A's CAS against the validated term-7 image fails.
```

After such a failure, re-reading must not silently adopt the new owner or term:
reconcile an unknown publication outcome, never convert reconciliation into a
transfer of authority.

The fields that must be inside the atomic comparison split into the authority
(fence-attempt identity, authorized prover node and incarnation, fence term)
and the proof subject (victim node and incarnation, slot and recovery
generation, frozen victim key, LUN scope).  Term and incarnation must defeat
ABA: ownership must not be able to leave and return with an indistinguishable
token.  Which owner field has to equal the local node depends on the state
machine's own roles — do not require the recovery-lease owner to be local if
the design deliberately publishes the certificate before claiming that lease.

One thing a descriptor CAS cannot cover: if membership can revoke the prover
**without** changing the descriptor's authoritative ownership state, the CAS
never sees that revocation, and a second unlocked in-core check just before the
CAS still has a check/use race.  Either revocation becomes effective through
the same durable ownership transition the CAS observes, or the commit is
serialized against the authority that revokes the incarnation.

---

## Part 2(b) — serializing a rejoin against recovery

**A software admission barrier is a legitimate place for this.**  Target
enforcement is not intrinsically required, and the distinction that makes the
barrier sound is: you cannot trust the old, unresponsive victim to obey a new
instruction, but you *can* require a newly starting successor incarnation to
follow the admission protocol before it issues any filesystem write.  That
assumes every supported entry path obeys the protocol; it covers no arbitrary
block-device writer and no participant that bypasses admission.

**"SEALED" is not, by its name alone, a sufficient release condition.**  If
sealing only freezes the list of the dead node's journal work, this schedule
destroys data:

1. the survivor seals the list of B's journal work;
2. B+1 observes SEALED and mounts;
3. B+1 modifies shared metadata block `M`;
4. the survivor replays B's older journal update to `M`;
5. recovery overwrites B+1's newer state.

Releasing at the seal is correct only if the seal *also* establishes the
serialization — recovery is complete, or recovery locks and exclusion are
already installed such that B+1 cannot touch conflicting metadata or reuse the
relevant journal slice until replay finishes.  Otherwise the release milestone
has to move to recovery-complete, or to recovery-locks-established.

A barrier demonstrated is not a barrier sufficient.  What it must precede is
more than "mount returned": mount-time recovery and superblock writes, journal
initialization or slice reuse, background workers and queued bios, DLM grants
that permit conflicting writes, and the timeout/failed-mount paths that can
leave work running.  Control-region writes needed to *participate* in admission
may be allowed when separately safe, but must not imply filesystem admission.
The seal must also name the recovery generation it belongs to — a seal from an
earlier recovery cannot release the present join.

**Registration is not admission, and the two must not be confused in both
directions at once.**  A successor may register before filesystem admission if
the protocol needs it, provided it issues no forbidden write.  But under a
registrants-only or all-registrants reservation, registering confers
target-level write eligibility — so it is not available to claim simultaneously
that the target is excluding B+1 because the survivor holds that reservation.
Where a proof depends specifically on target-enforced exclusive-write
eligibility, B+1's registration must not be able to invalidate that premise
unnoticed.

---

## Part 2(c) — the original ambiguous command

Observations, and exactly what each one establishes:

| observation | what it establishes |
|---|---|
| passthrough timeout returned | a local deadline expired |
| request freed / local completion callback ran | the initiator has ended that local request object |
| driver reports an abort succeeded | whatever that driver's contract says, and no more |
| matched target-confirmed task termination, with the transport ordering | that target task is terminated under the protocol |
| matched terminal command response | that command instance reached a terminal result; its status is a separate question |

"A successful abort at the initiator" is therefore too ambiguous to use.  As an
error-handler return code, a log line or `DID_ABORT`, it is not sufficient.  As
"the initiator received and validated the target's successful task-management
response for the exact task, and the transport guarantees the referenced
command cannot arrive or be reinstated afterwards", it is real termination
evidence — and the target having already accepted the command is precisely the
case a real target-side abort addresses.

Even then: abort is not rollback; the PR state may already have changed; a task
reported absent may already have completed; task termination does not prove the
original PREEMPT AND ABORT returned GOOD; and terminating the prover's PR task
is not retirement of the victim's writes.  Those are five separate conclusions.

**"Reaped" must mean more than "the syscall returned."**  It requires that the
submission producer is closed (no queued retry, retransmission, reinstatement
or error-handling path can generate another execution-capable instance), that
every outstanding instance is accounted for by a terminal response or a
protocol-confirmed termination, and that associated broader-scope management
operations are accounted for — an outstanding reset cannot be ignored because
the original request completed locally.  A timeout, a TCP disconnect, a missing
registration or an elapsed idle period establishes none of this.

The posture for a same-owner read-only resume:

> Do not commit while an unresolved operation can still invalidate the proposed
> proof or interfere with recovery.

That is discharged either by establishing termination, or by establishing
noninterference for every remaining possible execution state.  The second is
why the harmless duplicate in Part 1 does not require waiting forever on a dead
predecessor's response — but "the new boot has a different key" is only part of
a noninterference argument: it establishes nothing about already-selected nexus
abort work, or about disposal of resets the error handler generated.  With
neither termination evidence nor a complete noninterference case, **stay
blocked**.  There is no honest fixed timeout after which an unobservable target
operation becomes known dead.

And the resume must not manufacture its own evidence: observing the original
request's existing error-handling outcome is read-only; **issuing another abort
or reset is not**, and needs a separately authorized path.

---

## What is measurable on an appliance target

| obligation | rig test shape |
|---|---|
| duplicate keyed P&A behaviour | delay one command initiator- or network-side, exercise BOTH effective orders, capture keys, task identifiers, statuses, the resulting registrations and reservation, and the successor's I/O |
| commit-time ownership | pause between proof and publication, perform a takeover, release the publication; require failure, or an exact already-committed reconciliation — never publication under adopted authority |
| rejoin serialization | pause the survivor's replay AFTER sealing, let B+1 reach admission, and verify conflicting I/O and journal-slice reuse are still blocked |
| request termination | correlate the passthrough and error-handler events with the iSCSI command and task-management traffic, including retries and escalation |

None of these needs a transfer larger than the appliance's 512 KiB maximum.
A packet capture is evidence for the run it covers; the production commit
predicate still needs a usable termination signal or an audited return-code
contract, and an offline trace cannot supply one.

The honest support boundary where that contract is missing:

> initiator-visible behaviour tested on the identified firmware and
> configuration; safety additionally relies on the target's PR and
> task-management retirement and ordering contract.

If the contract is unavailable, or unsupported by what was observed, record the
retirement limitation.  Do not rename registration disappearance, a quiet
interval, or a locally reaped request as a retirement measurement.

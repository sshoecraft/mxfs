<!-- s72 design-consult ruling (Astra): the fence attempt's "a command may have run" marker is scoped to the term that armed it; the crash-cut harness predicts PR state from the rig's declared registration class plus per-lap evidence, and the two victim arms (destroyed / silent-but-running) are credited separately -->
# s72 design-consult ruling — crash cuts on a purging target, and the term-scoped arm

Consulted for `D-FENCE-CRASH-MATRIX-UNTESTED` after sweep s71a on the 2-node
TCP rig, whose QNAP target purges a node's PR registration when that node's
iSCSI session dies (PR generation unchanged).  Two questions: the cut-3/4
defect (a successor's taken-over armed attempt was never re-driven and its
mount failed), and what the harness may predict and require per cut on such a
target.  This extends `fence-crash-matrix-cuts.md`; it replaces nothing there.

## Hazards, as ruled

1. An inherited arm is not a submission by the successor.  Conflating them is
   the liveness defect.  Conversely, clearing inherited submission uncertainty
   must never turn an unexplained key absence into a proof of exclusion.
2. Taking over ownership does not take over a volatile result.  At cut 4 the
   successor cannot certify `PREEMPT_ABORT_DONE` or `EXCLUSIVE_WRITE_GATE` on
   the strength of what the dead prover might have done; it needs a new proof
   and the certificate names it.
3. A durable certificate is not an everlasting exclusion condition.  A kind-20
   certificate records a gate-based proof; if the gate is gone and the LUN is
   writable without it, the record is history, not execution authority.
4. Re-proving exclusion is prospective: it does not establish that exclusion
   held during a gap.  An artifact that depends on uninterrupted exclusion (a
   sealed manifest) needs its own validity argument or a rebuild.
5. Neither registration absence nor the PR generation is a boot boundary, and
   the generation is not a notification of every PR-state change: this target's
   purge leaves it unchanged.

The cut-3 refusal to replay without a certificate was correct fail-closed
behaviour.  The defect was the durable retry state leaving a recoverable
attempt permanently ineligible.

## The repair: submission state is per term

Preferred shape — an explicit split between current-term uncertainty and
prior-term history:

    takeover CAS (holder proved revoked, takeover otherwise permitted):
        prior_term_may_have_run  = old.prior | old.current
        fence_term               = old.fence_term + 1
        owner = prover = us; victim key and incarnation unchanged
        current_term_may_have_run = false
        stage = FENCING
    arm_submit CAS (this owner, term, stage, frozen victim), before the PROUT:
        current_term_may_have_run = true, durable

The automatic pre-command retry predicate accepts a descriptor whose CURRENT
term is unarmed, whatever the prior-term history; it never ignores
current-term uncertainty.  The prior-history bit is not a reconciliation
proof: it says an older term might have changed target state, and it forbids
reading key absence as that command's success.  Every consumer of the old bit
must be audited for which of the two it means.

Implementation check: the `NO_RESERVATION` / PRECOMMAND path must not arm the
new term.  If a reservation-form check ran after a fresh arm, splitting the
inherited bit would not help — the successor would arm itself before
returning "nothing issued".  (In the tree the reservation check precedes the
arm callback; no arm line for the taken-over slot appeared in the journal.)

Rejected shapes: clearing the single bit at takeover (sound only if the bit
is explicitly redefined as current-term state and every reader audited; the
history is lost); a retry keyed on volatile in-memory knowledge that "our
term submitted nothing" (not crash-closed — a re-mount refuses again);
deferring the takeover while another victim's single-holder gate is in force
(scheduling, not the repair; a dependency cycle risk).  A durable, named
PRECOMMAND wait with a wake-up on gate restore plus periodic retry is the
preferred scheduling; a longer mount timeout is not a repair.

After an inherited arm the successor may seek a new proof under its new term:
a present victim key that its own P&A consumes gives `PREEMPT_ABORT_DONE`; an
absent key gives nothing by itself; self succession, boot succession or the
sole-survivor gate give their own kinds with their own evidence; nothing
proving leaves an attempt that ends blocked under the existing policy.  Once
the new term arms or submits, its own ambiguity follows the existing rules.

## The harness on a purging target

**Declare the rig's registration-persistence class** (measured by
`tests/pr_session_drop_probe.sh`, recorded with the target, session topology,
method and date; refreshed when any of those change), and let the harness read
it.  Still, every lap collects the PR observations that substantiate its own
claims — the victim registration existed before the fault, is present or
absent at the cut as predicted, the prover's registration and reservation are
as predicted, and any command credited with consuming a key actually did — and
a mismatch is a precondition or coverage failure, never a silent branch
change.  The expectation selector is target class × victim fault mode ×
membership and boot-return order × intended fence branch × prover cut.

The PR generation is a valid "no command left" assertion for cuts 1-3 only
relative to a baseline taken after the setup registrations and with no
intervening generation-changing operation; the intent and arm CASes do not
move it.  At cut 4 an advance attributable to the gate P&A supports the gate
observation and establishes nothing about the victim's key, which was already
absent.

Predictions for the destroyed-victim sweep on a purging target (the purge has
completed before the parked cut; A1 the only live member at the cut):

| cut | descriptor / proof state at the cut | PR expectations |
|---|---|---|
| 1 pre-intent | no B1 attempt from this prover | B1 key absent; generation unchanged |
| 2 intent, unarmed | attempt durable, no certificate | B1 key absent; generation unchanged |
| 3 armed, no PROUT | attempt armed, no certificate | B1 key absent; generation unchanged |
| 4 proving result, uncertified | volatile `EXCLUSIVE_WRITE_GATE`; no certificate | B1 absent; A1 present; READ RESERVATION shows WE(1) held by A1's key; generation moved |
| 5 certified | durable `EXCLUSIVE_WRITE_GATE` | A1's gate in force |
| 6 sealed | FENCED with the kind-20 certificate; no claim | A1's gate in force |

After A is destroyed at cuts 4-6, the loss of A1's registration and of the
gate reservation is observed independently, never inferred from the class.

Successor obligations: cuts 1-4 — no durable B1 certificate exists, so the
successor establishes any required revocation of A1, then obtains and names a
NEW proof of its own term for B1 (on this schedule: A1 by the sole-survivor
gate, B1 by boot succession); cut 3 additionally shows the inherited arm did
not strand the attempt.  Cuts 5-6 — the certificate is taken over, but its
observed protection has lapsed: before work requiring exclusion the successor
needs a new valid gate proof bound to its current authority (`P239-GATE-
REPROVE` or equivalent) or an explicit recertification by another mechanism;
boot succession is never an implicit reading of the old certificate.  The
harness validates the path the implementation actually takes.  Taking control
of the recovery state is distinct from inheriting authority to execute it:
changing the owner, keeping FENCED or logging "reproved" does not make stale
evidence current, and at cut 6 a sealed manifest that assumes continuous
exclusion needs its own validity argument.  This is not a rule that every
certificate dies with its prover: a durable `PREEMPT_ABORT_DONE` stays usable
while its exclusion conditions continue to hold.

## The alive-but-silent victim is required coverage

To claim the `PREEMPT_ABORT_DONE` branch of cuts 4-6 on a purging target, the
victim's registration must be present and consumed by the prover's P&A: park
the victim's disklock heartbeat writer while its session and registration stay
up, with the victim genuinely running.  It counts as prover crash-cut coverage
for that branch (the prover is still crashed at those cuts) and is labelled
separately (target class, victim mode, fence branch, cut); the gate sweep
receives no credit for it and vice versa.  It requires: the frozen victim key
present immediately before the operation; the victim session up through it;
evidence the P&A consumed the intended registration; abort and exclusion
behaviour for the still-running victim; no unauthorised re-registration and
resumption by the fenced incarnation; at cut 4 no durable certificate and a
new-proof requirement after takeover; at cuts 5-6 a durable certificate naming
`PREEMPT_ABORT_DONE`.  Heartbeat silence alone does not credit the "partitioned
but running victim" property — the stale-I/O behaviour is demonstrated too.

The hazard named for this arm: on a purging target, destroying the prover can
remove the last registration and reservation, and a preempted but still-
running victim may then meet an UNRESERVED LUN — registration removal is not a
permanent write-deny list.  The arm must test the protocol's protection
against the old incarnation writing after that loss.  A later gate re-proof
stops future writes; it neither erases intervening ones nor validates an
earlier sealed snapshot, and the test must expose that distinction rather than
report success because a successor eventually reacquired a gate.

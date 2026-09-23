# Fence crash matrix — the cut set, the hold, and what a cut may assert

Design-consult ruling (Astra, session 68, 0.89.5) on the harness that
disposes of D-FENCE-CRASH-MATRIX-UNTESTED.  The question brought: six
prover cuts parked by a one-shot knob so the VM can be destroyed there, a
per-cut platter prediction, and a verdict of "certificate or a named
blocked state".  The ruling's binding points, in the tree's own terms.

## The cut set

Cuts 1-6 on the prover are accepted as a first tranche, never as closure of
the record.  No pair of them is redundant: the heartbeat sector can read the
same bytes at two cuts (3 and 4) while the target's PR state differs, and
the descriptor alone is too narrow a state to compare.

| cut | where | what it tests |
|---|---|---|
| 1 | after the victim-key check, before fence_intent | the pre-intent endpoint; not an intent CAS whose completion was lost |
| 2 | after fence_intent returned 0, **before arm_submit** | durably unarmed; must stay distinct from 3 |
| 3 | after arm_submit's CAS, before the PROUT leaves | **armed, not dispatched**: conservative treatment of the submission marker, not an in-flight command |
| 4 | after the P&A returned a proving kind, before fence_certify | the volatile-proof hole; verify independently that the P&A consumed the intended registration, never infer it from the cut number |
| 5 | after fence_certify returned 0, before the snapshot | takeover with a durable certificate and no sealed manifest; not a partially written snapshot |
| 6 | after the snapshot sealed FENCED, before the claim | execution-lease acquisition from a sealed manifest; the fence-attempt takeover is not a substitute |

A single atomic certify CAS has only the cut-4 or cut-5 persistent outcome
if its atomicity and durability actually hold; endpoint cuts do not test a
CAS that committed with its response lost, a CAS still pending when the
successor acts, compare failure versus transport failure, or a late
completion against a changed owner or term.  Those need fault injection or
delayed completion, and the matrix may omit them as crash laps only once it
establishes that pending I/O has drained before a successor acts.  The same
applies to the intent, arm, claim and every stage-advance CAS.

Direct I/O reads bypass the client cache, not the target's volatile cache;
they do not establish power-loss durability.

Cuts still missing after 1-6, each needing a matrix entry that names the
hook, the pre-crash effects, the pending requests, the durable state, the
takeover path and the assertions — never credited to an existing harness by
name: an actual in-flight P&A (submitted; acted on but response undelivered;
response lost with the prover alive); a partial snapshot and seal; replay
partially applied before its completion marker; each destructive action
completed with its stage advance not durable, and the converse (a stage never
durable before its prerequisite effects); a zero pending or completed with the
acknowledgement lost, including slot reuse and a late old-owner write;
competing or stale owners (losing takeover CAS, late certify completion, stale
execution lease, outstanding I/O when ownership changes).  An owner parked
inside the purge has already passed the replay boundary and covers none of
the replay, zero or execution-takeover boundaries.

## Cut 4 is recoverable here, but only by a NEW proof

The original certificate is lost and cannot be reconstructed from "key
absent".  Either later mechanism can supply a fresh proof under its own
prerequisites, and arrival order changes which proof becomes available
first, never the safety requirement.  A fresh durable certificate must name
the mechanism actually used; key absence plus a higher PR generation must
never be relabelled as the original P&A success.

Boot succession needs: a trustworthy mapping host → old incarnation → old key
→ slot; evidence the new boot supersedes rather than coexists with the old
incarnation (a cloned VM or duplicated identity must not satisfy it); the old
key absent across the relevant registrations under a reservation that
actually excludes it; assurance the old incarnation cannot reconnect and
regain write authority; and assurance that writes it already had accepted
cannot complete after recovery begins.  A partition is not a boot boundary,
session loss is not a boot boundary, a target that deletes registrations on
disconnect is not a boot boundary, and registration absence does not by
itself prove that admitted I/O was aborted or drained.

The sole-survivor exclusive-write gate needs: the protocol's own evidence of
"sole survivor", not merely missing heartbeats; the exact command submitted
and its successful completion (not a PREEMPT, a timeout or an inferred
success); the effective post-command reservation (correct LUN and scope,
plain WRITE EXCLUSIVE, the intended holder); evidence the all-other-
registrants eviction and task abortion occurred; and continued exclusion
through recovery, including reconnects and any later conversion back to an
all-registrants reservation.  A genuine P&A or WE fence excludes a partitioned
but running victim; physical death is not required.  The hazard is treating
the partition as proof of sole-survivor eligibility, or letting another
contender take write authority back.  Under an all-registrants reservation a
stale re-registration restores write access; under plain WE a registration
alone does not, but preempting the holder, changing the reservation or
relaxing it back does.  The harness checks those transitions, not "no
re-registration".  Partition and reconnect laps are required; killing both
VMs exercises neither.

## Assertions

- "Zero replay refusals after a certificate" is wrong.  A stale lease holder
  must be refused, a caller before the seal must not replay, and target-state
  loss can invalidate a durable certificate.  Assert instead that every actual
  destructive effect had the current exclusion evidence, the execution
  authority, the victim identity and the prerequisite stage; that a refused
  invocation performed no forbidden effect; and that the legitimate current
  owner progresses once the evidence exists.  Unexpected refusals on the
  intended path are liveness failures, never safety failures.
- "No progress lines before a certificate" is too weak.  Logs are not an I/O
  oracle and log order is not durable-state order; a successor may consume a
  certificate already on disk without printing the certification line.
  Correlate destructive actions with the authorisation evidence at admission,
  cover purge, grant release and zero as well as replay, and test that a
  takeover handles already-issued I/O.  A gate re-read followed by an
  unprotected delay does not close a lease TOCTOU race.
- "No zero without FENCED-or-later" is far too weak.  The zero requires the
  current exclusion evidence, the correct execution owner, GRANTS_RELEASED as
  its predecessor, the same victim incarnation and slot generation, and
  protection against overwriting a reused slot; a stale owner validating an
  old descriptor must not later zero a new occupant's heartbeat.  The zero is
  identity-bound and conditional, and the race is tested.
- "Certificate or blocked, never both" is wrong over a whole lap: a blocked
  attempt may later recover when the victim boots or the WE gate becomes
  available, and target-state loss can require blocking after a certificate.
  The expected outcome is defined per attempt, evidence epoch and observation
  point.  "Success or a named block" is also too permissive — an
  implementation that always blocks would pass — so each cut states whether
  it MUST recover, MUST block, or is order-dependent with its allowed
  transitions.
- The returning node's platter read can miss the state under test: mount and
  settle may change owner, term, stage and PR state before the read.  Capture
  the state at the cut, the quiescent post-crash state before recovery
  mutates it (an observer that changes no membership or PR state, or an
  explicit pre-recovery stop), and then the takeover transitions.
- MAY_HAVE_SUBMITTED needs live-prover faults, not only destroyed provers:
  a definite pre-command failure, an uncertain submission, a successful
  target action with the response lost, an arm CAS that fails or completes
  ambiguously.  Assert that durable arming alone never certifies, that
  pre-command retries are bounded and end in the specified durable verdict,
  that an uncertain submission is never blindly resubmitted under the same
  attempt, that a successor's new P&A requires proved revocation and a new
  term, and that a late completion cannot certify a different attempt.
- Keep the dirty-death replay oracle.  "Both nodes read the files" does not
  establish complete, exactly-once recovery, and cannot be required in the
  prover-only arm at all.

## The hold

A sleeping or spinning hold on the heartbeat-monitor path can contaminate
the experiment: a local self-fence or watchdog before the kill, PR or
session cleanup caused by it, an unrelated lease expiry, starvation of the
work that finishes the CAS or prints the marker, or a timeout path changing
the descriptor while the harness believes it parked.  In the two-node
sequence nobody is left to declare the prover dead, so the lap exercises
boot-boundary revocation only, never the certified-dead takeover branch;
the two are not both credited.

Preferred: a debug-only suspension that yields the thread, keeps the
continuation and the ownership, and lets nothing else advance the same
attempt while heartbeat service continues.  If a short blocking hold is
kept: prove it below every watchdog and liveness threshold, require the
destruction before it expires, verify that no self-fence, cleanup or PR
transition happened between the marker and the destruction, and reject a
contaminated lap rather than accept its recovery outcome.  The hook is
filtered by victim, slot, incarnation and term; a global one-shot that
catches the wrong attempt is not a deterministic test.

## Target restart

"Registrations survive" is nowhere near enough.  The lap must show that
APTPL is supported and active (not merely requested), and distinguish a
service restart from a target-host crash; that the latest complete
reservation state survives (holder, type, scope, nexus associations,
registration attributes) and in particular that a victim key removed by an
acknowledged P&A stays removed — restoring an older PR database resurrects
the victim; that persistence is measured before automatic re-registration
masks a loss (observe the REGISTER traffic, or hold the initiators off until
the restored state is inspected); that no unreserved access window exists
while the LUN is reopened; that old tasks are terminated or ordered (APTPL
preserves PR state, not the completion status of a pre-restart P&A); that the
PR generation is never treated as a durable epoch (it resets and wraps, and a
matching number does not make a pre-restart certificate current); and that
without APTPL the loss of exclusion fails closed for ordinary clustered
writes as well as recovery writes — a durable FENCED descriptor does not
authorise continued I/O because its sector survived.  Restart laps run around
P&A completion, certification and active recovery, not only on an idle
cluster.

## Bottom line

The gap is not a missing cut number.  It is treating descriptor state and
log lines as substitutes for current target exclusion, incarnation
revocation and execution ownership; the matrix covers those dimensions
together.

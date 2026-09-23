# The fence matrix's remaining gates, and the partial-replay cut

Design-consult ruling (Astra, session 85, 0.89.18) on D-FENCE-CRASH-MATRIX-UNTESTED:
what of the matrix still gates a 2-node TCP release whose bar is integrity and
stability only, and what the next lap must look like.

Three questions were brought, each with the tree's own evidence: whether the
record's own proposed next step measures anything new; whether the late-command
hazard is structurally unreachable on this rig; and which of the remaining
entries can actually corrupt data or hang a node.

## 1. "Lose the response, then kill the prover" is cut 4

The record's next step proposed arming the lost-response injection and then
destroying the prover, so that a successor would meet the ambiguous descriptor.
It measures nothing new. Both histories leave:

- the same durable attempt descriptor (FENCING, the submission marker set);
- the same COMPLETED PREEMPT AND ABORT at the target;
- no outstanding instance of that command;
- a destroyed prover, so its differing volatile belief is unobservable.

The equivalence rests on both histories having completed the same operation —
**not** on key absence being adequate evidence of retirement, which it is not.

Four narrow checks qualify it, and they are cheap:

1. the injected timeout must reach only the fencing caller — if it induced SCSI
   error handling, a reset or a reconnection, the histories diverge;
2. the ambiguous leg must not submit another command or persist another field
   between the loss and the kill;
3. the longer setup must not allow a registration or reconnection transition
   that cut 4 did not have;
4. the banked cut-4 laps must have run with the takeover marker conversion
   that is in the tree now.

Converting an inherited submission marker into a historical prior-term marker is
correct for proof attribution. It does not by itself revoke or drain an old
command, and must not be read as if it did.

## 2. The late-command entry is NOT closed by "the target purges on session loss"

The argument brought was: the target cannot be instrumented, a destroyed prover
loses its session, that session's registrations are purged and its task set
aborted, and a live owner is never taken over — so a predecessor's command
cannot execute after an ownership change. That argument is insufficient, for
reasons worth keeping:

- **Inability to delay the target is not a reachability argument.** Transport
  buffering, target scheduling, resource contention and recovery processing can
  separate submission, receipt and execution without anyone arranging it.
- **Session-loss cleanup needs a happens-before edge.** "VM destroyed ⟶
  eventually the target processes session loss ⟶ registrations purged and tasks
  retired" does not establish "the target has retired the predecessor's tasks ⟶
  the successor may activate the new recovery authority". Nothing measured so
  far orders those two.
- **A successor's fresh PREEMPT AND ABORT against the VICTIM does not retire a
  pending command from the PREDECESSOR's nexus.** Those are different task sets.
- **"Live owner" must not mean "owner not yet classified dead."** The rig
  already runs an alive-but-silent victim with a working storage session, which
  is exactly that distinction. A heartbeat timeout separates the two predicates.
- **Two nodes does not bound the successors to one.** A restarted incarnation of
  the prover itself is a successor, and it can start while the target still
  holds state associated with the old incarnation unless startup excludes the
  overlap.
- **Late execution is not automatically harmful, and that is the useful half.**
  The obligation is not "no old command may ever execute late" but **no old
  command may affect a later valid incarnation**. If the victim's key is reused,
  an old PREEMPT AND ABORT removes the victim's NEW registration and aborts
  legitimate new work — so key rotation has to actually prevent aliasing;
  naming commands by software term alone does not.

Acceptable closure is an explicit argument establishing ONE of **drain** (all
predecessor commands retired before successor-dependent work, with no sender
able to reintroduce them), **exclusion** (no permitted transition activates a
successor while an old sender or target task is still relevant), or
**harmlessness** (enforced command and registration lifetime rules make late
execution unable to touch the new incarnation) — backed by measurement of the
target properties and by exercising the code guards it depends on. A lap cannot
prove universal unreachability, and a target-delay stunt is not required.

## 3. What actually gates, ranked

Work-priority order, not a claim that lower ranks are less serious.

| rank | invariant, and the entries it consolidates | the failure it exposes |
|---|---|---|
| 1 | **Replay effects, durable completion and journal retirement are correctly ordered** — partial replay, replay complete with the marker absent, premature completion | a durable prefix replayed twice performs a non-idempotent allocation, free or link update twice; or a completion marker makes a successor skip an unapplied suffix and then discard the only recovery copy |
| 2 | **Slot reuse is generation-safe against every old destructive action** — zero pending, zero completed with the acknowledgement lost, stale execution lease, old writes crossing reuse | an old zero lands in a reused slot and erases the new occupant's journal; or recovery retries an old zero against a slot whose incarnation changed |
| 3 | **Only current authority can cause effective recovery I/O, across partition and reconnect** — competing owners, stale callbacks, outstanding I/O at an ownership change, late certify completion | two executors mutate the same metadata concurrently; a late successful completion is read as current authority; an unfenced old writer resumes while recovery is editing its metadata. A durable owner CAS alone excludes none of these |
| 4 | **A sealed manifest is complete, coherent and bound to the intended incarnation** — interior snapshot cuts, seal publication ordering | a partial or mixed-generation manifest is accepted as complete, omits required journal work or names the wrong journal interval, and recovery discards committed updates |
| 5 | **Target restart cannot silently invalidate admission or retirement** — APTPL and reconnect, conditional on which configurations are supported | reservations vanish while a survivor still trusts an old certificate; a fenced writer regains write access concurrent with recovery |

### Entries that should NOT stay separate gating laps

- **"Each destructive action completed without its stage advance, and the
  converse"** is not an endless family. Fold it into the three real commit
  boundaries — replay effects vs. completion, zero completion vs. reuse
  permission, manifest contents vs. seal publication — and for each establish
  (a) effects without the marker are safely repeatable or recognisable, and
  (b) the marker without its durable effects is unreachable, or detected and
  repaired. The second deserves the scrutiny: I/O completion is not durable
  completion, and the flush/FUA ordering is what makes the difference.
- **A losing takeover CAS** exposes no new corruption mechanism once the loser
  provably issues no authorised work and leaks nothing. Its expected failure is
  ordinary contention.
- **A late certificate response** is not a new target-state hazard. What matters
  is that a callback must never read "my operation succeeded earlier" as "I still
  own execution now" — which belongs to the current-authority gate above.
- **A completed zero with its acknowledgement lost** adds ambiguity and delay,
  not a corruption mechanism, provided reuse is interlocked and retry is
  incarnation-checked. It is a different entry from a zero that can still land.
- **A partial snapshot** needs one representative interior cut plus the ordering
  evidence, not every byte position; cuts 5 and 6 already hold the endpoints.

### Stability is not covered by proving "no corrupt write"

A path can preserve every byte and still fail the bar by waiting forever for an
acknowledgement that cannot arrive, holding a recovery mutex across an
impossible ownership transition, losing its only runnable recovery worker, or
livelocking after proof and storage access are both back. A declared, visible
safety block while proof is unavailable is legitimate. **Permanent blocking
after the prerequisites for recovery are satisfied is not a pace defect** — it
is a hang, and it is on the bar.

## 4. The next lap: durable partial replay with no completion marker

**Declared disposition: MUST RECOVER**, once the ordinary takeover, fencing and
storage prerequisites are restored. Before they are: MUST BLOCK replay and every
other destructive recovery action, while the node stays responsive. A permanent
block after the prerequisites become available is a failure, not a pass. The
legal two-node restart route that passed the sealed cut is sufficient; no third
node is needed.

**The workload has to require replay.** Committed journal work on the victim
whose recovery needs several distinguishable effects — creates, renames,
allocation and free activity, not one overwritten data block — with at least one
required effect in the prefix and one in the suffix. Several journal records are
not enough if every home effect was already checkpointed: establish that the
prefix will change home state and that the suffix is still necessary.
Acknowledged fsync results are the preservation oracle; interrupted unacknowledged
operations may take either crash-consistent outcome.

**The prover reaches ordinary execution first** — certificate, manifest, seal,
execution lease, replay begun. Manifest construction is deliberately out of this
experiment and must already be complete and valid.

**The hook** is one-shot, filtered by victim slot AND incarnation/attempt (never
by a reusable slot number alone), and placed at a replay boundary where it can
mean: *a nonempty prefix of an uncompleted recovery unit has changed home
storage durably, a nonempty required suffix has not been issued, and the unit's
durable completion marker has not advanced.* It stops scheduling further replay,
accounts for every replay worker and in-flight write, waits for the prefix's
writes and makes them durable through the required flush/FUA mechanism, writes
no completion marker, retires/zeroes/releases nothing, then signals and parks
for the destroy. A hook merely after parsing a log item or queueing a bio does
not establish durable partial application. If a durable progress cursor exists,
cut after effects the cursor does not yet cover; if every item is checkpointed,
choose a multi-write recovery unit with a real effects-before-checkpoint
interval — do not suppress a normal checkpoint and call the result a naturally
reachable crash cut.

**Pre-crash evidence, or the lap silently becomes "nothing applied" or
"everything applied":** the prefix changed home state and is durable; the
required suffix is not applied; the source journal is intact; no
completion/retirement marker became durable; no background worker escaped the
cut.

**Durable state at the destroy:** victim identity unchanged and named; fence and
manifest valid, complete, sealed; execution lease naming the old authority; a
nonempty durable replay prefix; the required suffix absent; replay completion
not durable; source journal retained; retirement/zero/reuse not advanced past
the incomplete replay.

**Takeover** goes through the supported route and may not manufacture a
certificate, clear a marker by hand or bypass the recovery path: new authority
under the ordinary term and lease rules, the existing proof requirements for
consuming sealed state, no retirement inferred from key absence, no inherited
submission history used as the successor's proof, completion observed absent,
then resume from a valid durable cursor or safely repeat the affected unit.

**Assertions.** MUST RECOVER: recovery finishes; every acknowledged fsync result
is preserved; the required suffix is applied; repeating the prefix has no
duplicate destructive effect; allocation, link and extent accounting stay
consistent; the filesystem accepts and persists new work afterwards — validated
by the application oracle AND the filesystem's own consistency check, because
"mounted successfully" is not sufficient. MUST BLOCK while the unit is
incomplete: no completion marker may permit skipping the suffix, no zero or
reuse may destroy the remaining recovery source, no stale lease holder may keep
issuing effective recovery writes. Allowed transitions are redo-the-prefix-then-
apply-the-suffix, or validate-a-durable-cursor-and-resume; forbidden is
"completion absent, assume the replay probably finished, retire the journal".
Stability: apart from the deliberately destroyed VM, no panic, shutdown,
deadlock or stranded worker, and no unbounded retry once the proof is available.
Finally remount through the normal path and verify again, to tell genuinely
persisted recovery from success visible only in the recovering kernel's caches.

## Bottom line for the ledger

Close the timeout-then-kill entry as covered by cut 4, subject to the four
equivalence checks. Leave late-operation exclusion open, pending an actual
invariant — drain, exclusion or harmlessness — rather than a target-delay stunt.
Take durable partial replay next, then generation-safe slot reuse. Do not reduce
the remaining integrity scope to those two alone.

# The fence matrix after the endpoint cuts — a real P&A whose evidence is lost, with the prover alive

Design-consult ruling (Astra, session 74, 0.89.11) on which fence crash-matrix
entry follows the six prover endpoint cuts, and what shape its injection,
assertions and non-vacuity gate must take.  The first-tranche ruling is in
`fence-crash-matrix-cuts.md` and is unchanged; this one works inside it.

## The entry, and why it is first

**A real PREEMPT AND ABORT acts on the live-but-silent victim, its successful
response is discarded before the fencing code can use it, and the prover
remains alive.**  The victim's incarnation and the prover's incarnation are
unchanged through the ambiguity phase.

It is not another cut-4 lap and must not be filed as one.  Cut 4 measured the
loss of a volatile proof *followed by the prover's death and bootstrap
succession*; that is banked.  It says nothing about what a still-running prover
does after losing the result of its own command.  The state this entry reaches:

- durable `FENCING`, with the current prover and term;
- the "a PREEMPT-family command MAY HAVE RUN" CAS durable;
- the target has actually performed the P&A;
- the fencing state machine has no proving response;
- neither endpoint has acquired a new incarnation that could supply
  succession evidence.

That is an ordinary transport-ambiguity state, not an exotic
simultaneous-crash state.  A wrong transition out of it admits recovery under
an invalid certificate; an unrecoverable or heartbeat-blocking error path out
of it is a stability defect.  The dangerous shortcut is turning the resulting
missing key into evidence that the unanswered command succeeded — or into
`BOOT_SUCCESSION_ABSENT` without boot-succession evidence.

## The order that follows from it

1. This entry: live prover, lost response.
2. A genuinely outstanding P&A across an ownership change — first submitted
   but not yet acted on, then acted on with the response still withheld,
   released after the ownership transition.  Unlike entry 1 these laps must
   retain real lower-layer outstanding work; entry 1 deliberately does **not**
   discharge that obligation.
3. Competing and stale owners, created by partition-and-reconnect: losing
   takeover CAS, late certify completion, stale execution lease, outstanding
   old-owner I/O.  DLM TCP disruption and storage-path disruption are
   exercised separately, and the reconnect is part of the lap, not cleanup.
4. A zero pending, then a zero completed with its acknowledgement lost,
   followed by slot reuse and the release of an old-owner write.  This comes
   before ordinary replay idempotence because a late raw write can damage a
   *new* occupant, and rejecting a stale stage CAS does not undo that write.
5. Replay partially applied, and every destructive-action/stage-advance pair:
   effects durable with the advance absent, then the converse — an advance
   must not become durable before its prerequisite effects.  The converse is
   never manufactured by having the injector falsely acknowledge an effect
   that never happened.
6. A partial manifest snapshot and seal: prefix construction, incomplete seal,
   restart and reconstruction.
7. Target restart and APTPL, replaying the proof and ownership boundaries
   against the target's actual persistence behaviour.  The purge-on-session-end
   observation this rig supplies is **not** transferable to an APTPL restart.

The ordering puts ambiguous exclusion and continuing old authority ahead of
reconstructible metadata prefixes.

## The injection

A one-shot, attempt-bound, **post-real-completion** result-loss gate in the PR
transport adapter, below the fencing code's result classification and retry
policy.  Its sequence:

1. bind the injection to one specific P&A submission;
2. run the normal PROUT path, unchanged;
3. receive and retain the real transport result in a diagnostic-only witness;
4. if it is the qualifying successful P&A result, withhold it from the
   fencing caller;
5. let the harness sample the boundary;
6. discard the success and deliver the existing ambiguous/no-response failure
   representation through the normal fencing error path;
7. admit subsequent attempts under harness control, without reinjecting.

If the real command fails or never produces the qualifying completion, the lap
did not reach this entry.  It is not helped along by synthesizing a success or
by silently selecting a later attempt.

The injected error carries no surviving success or proof fields, and it is the
representation the real unanswered-command path supplies — not "victim
absent", not "command not submitted", and not an arbitrary errno that happens
to take a convenient branch.

### Placement

    real PROUT submission -> real target operation -> real transport completion
      -> INJECT HERE -> fencing result classification -> fence_certify

Injecting before submission, by dropping the command, by skipping the PR
helper, after the fencing code has already accepted a proving kind, by
suppressing the arm CAS, or by suppressing `fence_certify` or a later durable
write — each is a **different entry**, and several are weaker ones.

The lower-layer request lifecycle completes normally; the result is withheld or
substituted at a process-context boundary where resource ownership is sound.
Losing the SCSI completion callback and stranding the request instead tests
leaked requests, recovery escalation or a wedged heartbeat thread.

This is a deterministic test of **response loss at the fencing consumer
boundary**.  It does not claim to reproduce every consequence of an iSCSI
response lost on the wire; midlayer retries, session recovery, resets and
genuinely outstanding commands are later entries.

The retained success is an oracle **for the harness only**.  Production
recovery must never consult it, and in this drop lap the original success is
never released later — releasing it would make this a delayed-completion lap,
which is a separate ledger entry even if it reuses the primitive.

### Identity

Bound at submission and carried immutably through completion: LUN identity;
fence slot **and slot/record generation**; victim node and victim
epoch/incarnation; victim PR key; prover node and prover epoch/incarnation;
the durable ownership/proof term; a unique logical attempt id; and the exact
PROUT command, service action and submission id.  A slot number alone is
inadequate.  Transport resubmissions are distinguished from a new fencing
attempt; the one-shot is reserved against the selected submission, and a
mutable slot is never re-evaluated at completion, or the injection catches a
new occupant or a successor's command.

### The retry latch, and what it must not do

A companion retry-admission latch stops the next state-changing PR submission
for this fence transaction long enough to observe the lost-result state.  It
must **not** stop the ordinary error handler, read-only reconciliation, an
erroneous attempt to certify, or the node's heartbeat indefinitely — otherwise
the injector itself enforces the safety property being measured.

Because this code runs on the disklock heartbeat thread, the existing blocking
park is only a short observation mechanism here: either keep the hold bounded
safely inside the remaining dead window, or make the latch defer the fencing
work without parking the heartbeat.  **A prover that goes stale because the
injector held its heartbeat is not the live-prover lap.**

### Two-node reachability

The entry REQUIRES the prover to stay alive through the ambiguity and the
recovery-policy observation.  No third node is needed: the victim is
alive-but-silent as in the existing arm, the prover performs the P&A and
receives the injected ambiguous outcome, and management access observes both
machines and the target.  Destroying the prover at the marker collapses the lap
back toward the banked crash/bootstrap case.  A destroy-and-fresh-boot tail
afterwards is useful but is labelled bootstrap recovery; it is not evidence of
an online successor taking ownership while the old prover has outstanding work.

## Assertions

Immediately after the loss, before any new proving event: the durable arm
remains set (an ambiguous result cannot undo "MAY HAVE RUN"); the transaction
remains uncertified; no `SNAPSHOTTING`, sealed `FENCED`, execution claim,
replay, destructive cleanup or slot zero is authorised by this transaction; the
owner and term remain those the durable ownership protocol established; the
error path does not treat this as the preintent/prearm "no command ran" class;
and the victim's registration disappearance is observable but is **not**
accepted as the missing proof.

Downstream writes are not suppressed to make those true.  An erroneous
transition is allowed to execute far enough to be detected, and it fails the
lap.

Two relabellings are forbidden outright:

> "The victim key is absent now, therefore my unanswered P&A succeeded."

> "The victim key is absent now, therefore this is `BOOT_SUCCESSION_ABSENT`."

A timeout, a reconnect, another READ KEYS or a new local retry number
establishes neither a new victim incarnation nor boot succession.  The
diagnostic witness proves to the *test* that the command acted; it does not
make that fact available to the *protocol*.

From the durable armed `FENCING` record a successor may conclude only that a
PREEMPT-family command may have run and the previous attempt's effects cannot
be treated as nonexistent.  It may not conclude that the old attempt returned a
proving kind, that the old term was certified, that absence transfers the old
proof into its new term, that gaining ownership drained old requests, or that
an old completion authorises the new owner's execution.  In this entry there is
no old durable certificate to inherit.

### The verdict is in two parts

**A — ambiguity handling.**  Prove the normal error/reconciliation path actually
ran after the injected loss; holding it at the gate is not evidence.  Then
either a separately identified, valid **new** proving event occurs and normal
certification follows, or the code reaches the specifically expected
unresolved-proof state with no unauthorised progress.  An arbitrary named block
is not accepted: its cause must be the missing exclusion proof, not a stuck
hook, a dead heartbeat, an unrelated CAS error or an exhausted harness timeout.

**B — progress after a valid recovery opportunity.**  With the injection and
the latch removed, the lap must show bounded progress through the actual
certify/snapshot/seal/execution completion path once the predeclared stimulus
supplies a proof opportunity the implementation is supposed to accept — not
merely a retry message.  Bounds are set before the lap from the relevant
retry/lease/dead-window policy, and a matched uninjected control is run.

It is not predeclared that another P&A against an absent key must produce a
proving result unless that is the measured, accepted target contract, and no
new absence proof may be invented to make the test finish.  Where the live path
has no valid fresh-proof mechanism, the honest report is **"ambiguity safety
demonstrated; live recovery not demonstrated"**, with the banked fresh-boot
succession path exercised as an explicit recovery tail.  That defeats an
implementation that always blocks; it does **not** upgrade the result into
automatic live recovery from a lost response.

So: holding safely forever is not a PASS; certifying by relabelling absence is
a FAIL; refusing to invent proof in a genuinely unprovable state is correct;
and continuing to block once the specified valid proof opportunity exists is a
liveness failure.

## Non-vacuity

The admission precondition is not "we saw the marker".  It is: **this exact
armed attempt really completed a P&A against the still-live, same-incarnation
victim; the real successful result was withheld from the fencing state machine;
the prover remained alive; and no later attempt supplied proof before the
ambiguity observation.**  Each clause needs its own evidence.

*Before the command*: the victim's matching registration exists on this LUN;
its iSCSI session and incarnation are live and unchanged; the writer is
generating real target I/O rather than looping through cached operations; and
the expected `FENCING` record, owner/term, victim identity and arm are present
in target-backed state under the tree's durability contract.  A cached slot
structure, or a log line saying the arm is durable, is not enough.

*At real completion*: an immutable command witness holding the bound identity
tuple, the actual opcode and service action and keys, the real transport
completion status with its sense/result fields, evidence that the selected
lower-layer request completed, and evidence that no successful result was
published to the fencing caller.  The hook's causal location matters more than
log order: the witness state must be unreachable without passing through real
submission and real completion.

Correlate that witness with a target-backed PR observation showing the expected
registration transition, and confirm the victim's session did not end or change
incarnation in between — otherwise session purge is a competing explanation.
**READ KEYS alone proves neither that the P&A happened nor that tasks were
aborted**: registrations are removed for other reasons, and PREEMPT is not
interchangeable with PREEMPT AND ABORT.  A victim-side fsync message is not an
exclusion oracle either; prefer an identified post-boundary device write and
its actual target outcome under the old registration, and prevent or detect
victim re-registration during the observation.

*At the fencing boundary*, read through a target-backed, non-stale path while
the transition is gated: armed `FENCING` present, `fence_certify` has not made
`SNAPSHOTTING` durable, no seal and no execution claim, record generation and
identities still matching.  A fresh read establishes visibility, not power-loss
durability beyond the tree's own flush contract.  Then observe the next
state-machine actions and attribute every new command and proof to its own
attempt — sampling only while the result is withheld tests the gate, not the
recovery.

*Reject rather than grade* when: the victim registration disappeared before the
selected P&A; a session teardown or reboot explains the disappearance; the real
P&A did not produce the required completion; the successful result leaked to
the fencing caller; an unobserved retry supplied proof first; the owner, term,
incarnation or slot generation changed before the intended observation; or the
prover crossed into a stale/dead condition because of the hold.

## Bottom line

The decisive delta from cut 4 is not another pause location.  It is real P&A
effects, lost protocol evidence, and continued execution by the same live
prover.  Establish that delta causally, then test the normal error path without
letting either the injector or a fresh boot conceal its behaviour.

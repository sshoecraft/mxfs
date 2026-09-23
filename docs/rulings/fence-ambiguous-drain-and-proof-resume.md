# Resuming proof after a lost PREEMPT AND ABORT response — the drain obligation

Design-consult ruling (Astra, session 75) on the liveness half of the
lost-response ambiguity: whether a live prover that has lost the response of its
own PREEMPT AND ABORT may acquire a *fresh* proof of exclusion, and what such a
proof must establish.  The entry's shape, injection and verdict are ruled in
`fence-lost-response-live-prover.md` and are unchanged; this one answers the
question that ruling left open, and which the ledger record names as the reason
the record stays open after the hang was fixed.

## The state, restated

A issued `PERSISTENT RESERVE OUT / PREEMPT AND ABORT, rk=A, sark=B` against B.
It executed at the target — B's registration was removed and its task set
aborted — and the response was lost.  A is alive, same incarnation, same term,
carrying a durable "may have run" arm and no proving response.  B never
rebooted.

A refuses to certify, refuses to replay B's slice, and (0.89.11) marks the slice
`RECOVERY_BLOCKED` so waiters fail fast instead of hanging.  Nothing is
corrupted.  What is unfixed is that A now blocks forever: B's slice is never
recovered, B can never mount again, and the cluster is permanently one node.

## The two facts a certificate must rest on

Certification needs **both**, and they are separate:

1. **Admission closed** — B cannot obtain permission for a new write during
   recovery.
2. **Old work retired** — B's *previously accepted* writes can no longer
   introduce an effect that races with the recovery.

A Write Exclusive reservation held by our key establishes (1).  It does not
establish (2).  The sole-survivor exclusive-write gate, whose PREEMPT AND ABORT
carries `sark=0`, aborts the task sets of **the registrants it removes** — and
B is not one of them, because our own unobserved predecessor already removed it.
So the gate, on its specified scope alone, gives (1) and not (2).

## Absence is not a drain certificate

`READ KEYS` reports registration state.  It does not report why a registration
disappeared, which command removed it, or whether an earlier command is still
executing its abort work.  Three causes of B's key being absent, and what each
gives:

| cause | drain conclusion |
|---|---|
| our predecessor P&A | its *successful completion* carries the abort guarantee; earlier visibility of the removal does not |
| B unregistered voluntarily | **none** — changing the key to zero retires no work; the live-write hazard remains |
| nexus-loss cleanup | depends on the transport's task-retention rules and the target's cleanup ordering; removal alone is insufficient |
| target restart, administrative purge, failover | each needs its own analysis under that event's task, reservation and cache semantics |

The voluntary-unregistration row alone defeats the general implication, so the
absent-key observation may never be promoted into a drain certificate for the
whole class.

Two claims must not be conflated: that the PR-state transition is indivisible
*with respect to other PR operations*, and that nobody can observe the resulting
PR state until the associated task abortion has completed.  Only the second is
the one we need, and the first does not imply it.  Whether SPC's "uninterrupted
series of actions" prohibits a concurrent PERSISTENT RESERVE IN from seeing the
removal before the abort drain completes is **genuinely uncertain** and must not
be asserted from that phrase; the sections to read together are persistent
reservations / preempting and preempting-and-aborting, the PREEMPT AND ABORT
service action's completion requirements, PERSISTENT RESERVE IN / READ KEYS, and
SAM's task-abortion and task-management completion rules.  Until that argument
exists in writing, the implication is not available.

The tree's existing measurement (with a victim write in flight, SA 0x05 blocked
12.3 s and the write landed 126 us *before* the PR completed, against SA 0x04
returning in 0.2 ms with the write landing 12 s *after*) establishes that the
response was withheld until the write passed the abort barrier.  It does **not**
establish that a PR IN or a later PR OUT cannot observe and use the modified
registration state before that barrier.  Those are different claims.

## What can supply the drain

Ranked, with the ruling on each:

- **(a) a second PREEMPT AND ABORT naming the absent victim** — in this
  reservation state, with a non-zero service-action key matching no
  registration, expect RESERVATION CONFLICT.  The conflict proves nothing: not
  that the predecessor completed, not that B has no tasks, not that B's writes
  drained.  Re-registering B's numeric key on a nexus we control and preempting
  that would not help either — **abort scope follows the affected nexuses, not
  the historical meaning of a key value**.

- **(b) LOGICAL UNIT RESET** — the strongest broadly specified candidate.  Its
  architectural scope is the tasks for the addressed logical unit across its
  I_T nexuses; registration is *not* the membership criterion.  An ordinary
  conforming LU reset preserves persistent reservations and registrations
  (APTPL is about power loss, not about surviving a reset).  An I_T NEXUS RESET
  issued for our own nexus is the wrong scope and does not reset B's.

  Scope traps: resetting one B nexus is insufficient if another can hold old
  tasks; resetting one exported logical unit does not reset a different logical
  unit sharing the same backing store; and a local API returning "reset request
  accepted" is not the evidence — the transport/SAM completion saying the task
  management function completed is.

  Collateral hazards, all of which are prerequisites rather than footnotes: the
  reset aborts our OWN outstanding transactions and metadata writes, and "B is
  fenced" does not make those ambiguities safe; a quiesce that waits on the
  already-blocked journal can deadlock; a reset need not complete in any useful
  time when the backend is broken; expected reset unit attentions must be
  handled as events rather than retried and forgotten, and unexpected
  reset/reservation/registration events must invalidate the assumptions they
  touch; and any lower-layer *semantic CDB reissue* must be audited, because an
  old PR operation resurrected after the final validation defeats everything.

  Reset and drain are **not** rollback and not a cache flush.  An aborted write
  may have taken effect partially or completely; recovery has to tolerate that.
  The guarantee being bought is only that the old task cannot subsequently
  introduce an *unordered* logical write under recovery.

  The defensible sequence: keep recovery blocked; stop uncontrolled writers and
  any semantic reissue of old PR commands; establish the admission barrier;
  quiesce our own ordinary I/O; make the reset's command boundary durable;
  issue the reset and obtain its successful task-management completion;
  revalidate the PR state, our authority and the target's events; then permit
  recovery **while still holding the admission barrier**.  Reverting to
  write-exclusive-all-registrants and admitting B before recovery is safe
  reopens the problem.

- **(c) relying on a reservation re-check when a queued task executes** —
  **rejected.**  There is no portable guarantee that a task admitted before a
  reservation change is re-checked before backend submission, before media
  modification, or at completion.  The very existence of the distinction
  between PREEMPT and PREEMPT AND ABORT is the argument: changing reservation
  state does not retire existing work.  There is no universal "BIO boundary" in
  SPC or SAM.

- **(d) qualifying this target's own contract by measurement** — legitimate for
  a *qualified* target implementation, version, backend and configuration, and
  never promotable into a promise about arbitrary targets.  One timing result
  does not establish it: three explanations must be separated — the gate really
  drains work from already-unregistered nexuses; the gate merely waits behind
  the predecessor, whose drain does the work; or the order was accidental (host
  serialization, one backend queue, a device lock, timing).

  Two cases are required, and **the second is the essential one**: (i) remove B
  by P&A, pause before its abort barrier finishes, and issue the observation and
  the gate concurrently; (ii) admit a B write, unregister B *voluntarily*
  without aborting it, keep the write outstanding, and issue the gate.  Passing
  only (i) does not justify a general absent-victim gate.  Hold the write at
  more than one execution stage, use queue depths that rule out head-of-line
  blocking, and confirm the host is not serializing the experiment before the
  target sees it.  If the gate completes while the held write can still modify
  data, the drain claim is falsified; if it waits, find out *why* — waiting once
  is not proof.

- **(e) two other mechanisms** — recovering the *original completion*, if a late
  or transport-retained response can be bound unambiguously to the original
  command and still-current authorization (this is response recovery, not
  re-execution); or a target-side fence-and-drain operation scoped to the
  victim's *task contexts* rather than its registrations, which could be far
  less disruptive than an LU reset but needs an explicit target contract.

  Not substitutes, in any combination: session disconnection, initiator
  power-off, waiting an arbitrary number of seconds, TEST UNIT READY, an
  ordinary SYNCHRONIZE CACHE.  Killing the initiator does not retract writes the
  target has already accepted.

## The continuation

A separately authorized proof-acquisition continuation is materially different
from reopening ordinary retry, and the structure is sound.  Its invariants:

- the prover incarnation and authorized term match at dispatch **and again at
  proof commit**;
- the original uncertainty stays recorded until a valid covering proof
  supersedes it;
- every side-effecting command has a durable pre-submission boundary — the
  reset included, because losing a reset response is not evidence that it
  drained anything;
- responses are correlated to exact operations, never to "the current attempt";
- a stale callback cannot unblock recovery;
- a lower layer cannot later execute an uncontrolled earlier PR command;
- recovery is unblocked only when the whole proof predicate is satisfied.

**The lost gate response is its own trap.** After an unobserved *successful*
gate the reservation is already Write Exclusive held by our key, so a
continuation that accepts only the all-registrants type as its starting state
strands itself a second time.  The reconciliation has three arms: sole-owner
all-registrants — eligible to attempt the gate; the required write-exclusive
state already present — establish the present admission predicate but **do not
infer the missing drain**, and proceed through an independently valid drain;
anything else — stay blocked unless a separately authorized rule covers it.  Do
not resend the `sark=0` all-registrants transition against a reservation that is
no longer of that type.

**There is no semantic bound on nested ambiguities.** Every new command can
execute and lose its response.  A linear attempt sequence with a covering-proof
predicate avoids recursively nested implementation state — a later successful
full-scope drain makes the earlier execution-history uncertainties irrelevant to
safety — but no state machine guarantees eventual recovery under unlimited
response loss.  What is required is a stated eventual-response assumption for
successful recovery, plus a bounded operational failure path when it does not
hold.  A durable command boundary prevents unsafe forgetting; it does not
manufacture liveness.

## Bounded failure as the third outcome

There are three results, not two: exclusion proved and recovery proceeds; proof
acquisition still pending; proof acquisition failed within policy and the
affected filesystem fails closed.  A deadline that moves the second to the third
is honest only if it never permits recovery on weaker evidence, completes
affected waiters with defined errors, stops new operations silently re-entering
an indefinite wait, preserves the uncertainty and ownership records, produces
explicit health state, does not silently authorize takeover because the
filesystem declared itself failed, and has a **documented restoration
procedure** that obtains real proof — a controlled LU-wide drain and
revalidation, recovery of the original completion, or supported storage
maintenance with appropriate exclusion.  "Clear the ambiguity flag and retry the
mount" is not a restoration procedure, and renaming the condition improves
observability without improving recoverability.

The honest release statement, where the fresh-proof mechanism is not universal:
*ambiguity safety and bounded failure handling are demonstrated; automatic live
recovery is supported only where the specified fresh-proof mechanism succeeds,
and otherwise a filesystem outage and the documented restoration procedure are
required.*  If the requirement is that the peer always rejoins automatically
without such an outage, that statement does not meet it, and the choices are to
implement a valid covering drain, restrict the supported targets and fault
assumptions, or change the requirement — never to reinterpret an absent
registration as proof.

## The recommendation

Pursue **gate + a correctly scoped, acknowledged LU reset + post-reset
validation**, with our own quiescence and the unit-attention/reissue handling
treated as prerequisites rather than follow-ups.  In parallel, investigate the
target's PR serialization directly in its source: it may yield a cheaper answer
for the specifically identified predecessor case — but that conditional result
must never become a general absent-key certificate.

---

# Addendum — the shipping target is an appliance, and a reboot is not a drain

Second consult (Astra, session 75), after two facts came to light that remove
two of the four routes above.

## What removed them

**The target under test is a closed-source appliance.**  `data/rigs.json`
declares the 2-node TCP rig's LUN as a QNAP TS-453 Pro iSCSI target.  The SCST
reading below is therefore background and not a contract for the shipping
configuration — though it is worth recording, because it shows the ordering the
standard would not give does exist in at least one implementation:

> In SCST 3.11.0-pre (`/src/scst`), PR IN and PR OUT both take
> `dev->dev_pr_mutex` (`scst_pres.h:72`, `scst_pres.h:87`, both plain
> `mutex_lock`).  PR IN takes it at `scst_local_cmd.c:799` and holds it across
> the READ KEYS.  PR OUT takes it at `scst_local_cmd.c:900` and releases it at
> `:985`, *after* the service-action switch returns — and
> `scst_pr_preempt_and_abort` (`scst_pres.c:2288`) does its
> `wait_for_completion(&cmd->pr_abort_counter->pr_aborting_cmpl)` at `:2313`,
> inside that window.  So on SCST a concurrent READ KEYS from another initiator
> cannot observe the removal before the abort has drained.
>
> Two other facts from the same reading.  `scst_pr_abort_reg` aborts through
> `scst_rx_mgmt_fn_lun(sess, SCST_PR_ABORT_ALL, ...)` for the registrant's own
> session and LUN, and `__scst_abort_task_set` walks only that session's command
> list filtered by `tgt_dev` — **one I_T_L nexus**, confirming that a
> `sark=0` gate aborts nothing belonging to an already-unregistered victim.  And
> `scst_lun_reset` → `scst_process_reset` (`scst_lib.c:13217`) walks
> `dev->dev_tgt_dev_list` — every nexus bound to the device, across all
> initiators — with no reference to the registrant list at all, confirming that
> an LU reset has the scope a preempt does not.

**The measured route is not runnable either.**  The tree's in-flight A/B
discriminator (`tests/fence_inflight/inflight_ab.sh`) holds the victim's write
in the target's task set with `dm-delay` under the backing store and times the
PR completion from an ftrace probe inside the target.  Both require owning the
target.  On the appliance neither is available, and its maximum transfer is
512 KiB, so a single long identifiable write cannot be held either.

## The narrower defect, and the ruling on it

Treating this as "no fresh proof exists, therefore blocked forever" is wrong as
a description of the code.  The ambiguous slot is **never revisited by
anything**: it is deliberately not armed for retry (correctly), and every other
proof mechanism is reachable only from a different classification.  So even when
a proof becomes available, nothing looks.  That reachability defect is real and
a read-only same-owner revisit is the right shape for it.

**But the proof such a revisit would consume is not sound as it stands.**

> A host reboot establishes that the old incarnation has ended.  It does not
> establish that the target has finished retiring the commands from its old
> nexuses.

The adversarial schedule: the target accepts victim write W; the key disappears
with no completion witness for task retirement; the victim reboots and publishes
a new boot identity; its new initiator uses a different session identity, so the
target still retains — or is still processing the termination of — the old
session; we certify and begin recovery; W finishes too late.  The 512 KiB
transfer limit does not bound W's execution time.

The iSCSI terminology is load-bearing and must not be blurred: full **session
reinstatement** terminates the old session's active tasks; **connection recovery
/ reinstatement and task reassignment** can *preserve* tasks; and a genuinely
new session with a different ISID need not replace the old session at all.

So a succession proof must establish four things, not one:

1. **actual incarnation succession** — an authoritative, non-reused boot
   identity linked as the successor of *that exact* victim incarnation.  A
   different UUID is not an ordering, and initiator-name reuse is not evidence;
2. **complete nexus coverage** — every old session or path that could issue a
   write to this LU is accounted for.  A host-side disconnect, or one successful
   new login, is not that;
3. **completed target-side retirement** — the old sessions' tasks have reached a
   termination boundary whose contract excludes later logical write effects;
4. **publication ordering** — the durable successor witness the fence consumes
   is published *after* that retirement boundary, not merely after the successor
   kernel starts.

A standards-defined, initiator-observable completed operation may supply the
boundary in (3) without target source or tracing, but the applicable completion
semantics have to be identified and the actual login/teardown sequence checked
against them.  **No successful login is a barrier by assumption.**

Three corollaries that close off the tempting shortcuts: registration
disappearance and the PR generation are **not** task-retirement witnesses;
correctly ordered destaging of an already-completed cached write is not the
problem, a late old *logical write effect* is; and the twelve banked crash-cut
laps support path coverage and integrity under those schedules but do not
establish *successor boot publication implies target retirement complete*.

## Guards the revisit itself needs

The read-only sweep is not where the hazard is; converting insufficiently scoped
observations into durable authorization is.  Required bounds:

- **atomic ownership validation** — commit the certificate conditionally on the
  exact slot, attempt, victim incarnation, prover incarnation and owner term
  still matching, and keep the recovery subject to that ownership epoch.  A
  check taken before the sweep is not enough;
- **preserve the no-retry invariant** — never reclassify the slot into a state
  that re-enables ordinary retry, and never retroactively label the lost command
  successful.  Record the new proof's own kind;
- **use historical succession evidence, not a current boot id** — a genuine
  irreversible succession fact stays valid even if the successor itself reboots
  later, so a stale record can still be useful; two differing boot ids carry no
  ordering at all;
- **serialize rejoin against recovery** — certifying that incarnation B is dead
  does not authorize incarnation B+1 to write concurrently with the recovery,
  and one more READ KEYS immediately before the certificate does not close that
  race;
- **account for the original ambiguous command** — rebooting the victim does not
  cancel a PR OUT still pending on the prover's own nexus; if it can still
  execute, key reuse could let it affect the successor;
- **audit the "read-only" claim** — a PR IN opcode is read-only, but the
  reconnect and SCSI error-handling path around it may not be.  The sweep must
  not implicitly reinstate a session or escalate a timeout into a disruptive
  task-management function or reset, and its polling, resources and reporting
  time must be bounded.

## The verdict this fixes in the test

- **no valid proof** — blocking is *correct*, and a certificate appearing is a
  FAIL;
- **a new boot identity alone** — still insufficient;
- **a complete, valid succession and retirement witness, with stable
  ownership** — the resume path owes recovery within its documented operational
  bound.

The earlier ruling's "exercise the banked fresh-boot succession path as an
explicit recovery tail" needs exactly that qualification: it permits using an
*independent* proof; it does not establish that an ordinary host reboot supplies
one.

## What this makes of the existing boot-succession fence

If the shipped boot-succession fence certifies from boot identity plus
registration absence plus a write-exclusive-form reservation — which is
admission, not retirement — **its retirement premise is an unresolved safety
gap**, and that is a defect in its own right rather than a limitation of the
resume path.

Restricting the *supported fault assumption* is honest once safety is separated
out: "no automatic recovery while the original victim stays alive and silent" is
a legitimate, explicit support limitation.  "The victim host reboots" is not yet
a substitute for it on the facts available.

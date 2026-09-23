# A local authority lease, and where a software gate stops being a proof

Design-consult ruling (Astra, session 87, 0.89.20), answering how to fix the
measured defect in which a fenced-but-undetecting node wrote to an unreserved
LUN. It continues `early-revocation-ownership-epoch-split.md`, whose §1 named
this ordering as an open hazard; the ordering has now been measured and the
bytes read back off the platter.

## The ruling

> Yes: an irrevocable, locally enforced expiration of storage authority is the
> right shape. But copying that predicate into a timer and a few write paths is
> not yet a complete fix.

Four properties are required:

1. A conservative ownership deadline, backed by the rules under which peers may
   revoke ownership — not merely by a successful heartbeat.
2. Expiration that cannot be undone by a late heartbeat, a late completion, or a
   resumed worker.
3. Coverage of every path that can mutate the LUN, including deferred work and
   **coordination** I/O.
4. A handoff rule under which old-epoch I/O has finished or become incapable of
   executing before recovery or new ownership proceeds.

It also draws a limit around the fence certificate this build mints:
`PREEMPT_ABORT_PROVEN_V1` proves the target performed that revocation. **It does
not by itself prove continuing exclusion after the protecting reservation
disappears.** If `proves_excl=1` authorises journal replay, its meaning needs
that additional lifetime guarantee.

## 1. The local quantity, and three things that were wrong about it

`hb_last_ok_ms` is a starting point, not the answer. The predicate has to mean

> this incarnation has not allowed its authority to lapse, and its latest valid
> renewal gives it authority until deadline D

and not

> a heartbeat write succeeded recently.

In particular **a heartbeat write succeeding on an unreserved LUN is not
evidence of renewed ownership**, which is exactly the state the measured defect
leaves behind.

The authority state is:

    ADMITTED(epoch, deadline)
        | expiration, explicit revocation, fatal ownership error
        v
    CLOSED(epoch)  ->  WITHDRAWN(epoch)

and only a fresh coordinated admission creates `ADMITTED(new_epoch, new_deadline)`.
`CLOSED` takes effect immediately for the admission of I/O; the full withdrawal
may follow asynchronously.

**The anchor is wrong if it is the completion.** Stamping the deadline when the
compare-and-write *completes* lets this sequence make the local heartbeat look
younger than the one peers can see: the update becomes visible at the target,
the completion is delayed, peers age that heartbeat, and only then does the node
stamp "now". Derive the deadline from a timestamp captured **before** issuing
the heartbeat that succeeded — or bound the completion lag and subtract it.

**Expiration must be checked where authority is used.** Correctness must not
depend on an expiry timer running, because a timer and a heartbeat thread can be
stalled along with the rest of the VM. Every final I/O-admission check evaluates
*state is ADMITTED*, *work belongs to this epoch*, *now is before deadline* — and
if time has expired, that check closes the epoch itself and refuses. A timer is
still worth having, for prompt withdrawal and for waking sleepers when there is
no I/O at all. This is what handles the quiet victim: its first attempted write
discovers the expiration with no PR access whatsoever.

Also required, and each is a way the epoch could be resurrected:

- a renewal is accepted only while the previous authority is still valid;
- a completion arriving after the previous deadline cannot revive the epoch,
  even if no timer ran;
- the heartbeat worker checks expiration **before** sending another heartbeat
  after a stall;
- expiry and renewal are serialised, so a concurrent renewal cannot reopen a
  closed epoch;
- an unknown or zero heartbeat timestamp must not read as "fresh" for a mounted
  filesystem.

**Local freshness is only sufficient against a compatible revocation protocol.**
The remote-side property that has to hold is: *an accepted renewal prevents peers
from completing a conflicting ownership handoff before that renewal's protected
interval ends.* A peer must not fence from an obsolete heartbeat snapshot while
ignoring a newer valid renewal, and any other revocation path — a fence driven by
TCP failure alone, say — must honour the same lease boundary or supply
independently durable exclusion. Reusing the existing bootstrap-readiness
predicate does not establish any of that.

## 2. The timing interval, and why a ratio is not a derivation

Different clock origins are not the problem; elapsed-time comparisons do not need
synchronised wall clocks. With ideal clocks and a local anchor that precedes the
peer's observation, the local deadline does expire first — but that ordering is
not established by the nominal `31 * 2000`. Completion lag, timeout-counting
semantics, clock behaviour, stale observations and outstanding I/O all intervene,
and the dangerous interval must be closed **before the fence is treated as an
ownership handoff**, because on this target the reservation cannot be counted on
to survive it.

The budget has the shape

    Δ + L / (1 - ρB) + J + Q  <  R / (1 + ρA)

where `R` is the remote algorithm's proved minimum protection interval after the
relevant renewal, `L` the local authority interval, `ρB`/`ρA` the worst-case
slow/fast fractional clock error on victim and prover, `Δ` the maximum lateness
of the local anchor relative to the renewal event, `J` the maximum delay in
enforcing closure, and `Q` the maximum time for already-admitted old-epoch I/O to
become incapable of executing.

Consequences worth writing down:

- **`R` is not automatically 62 s.** The peer's counting, sampling, revalidation
  and alternate death paths all have to be audited before that number is used.
- Anchoring the renewal before submission removes positive completion-anchor lag
  from `Δ`.
- Checking the time at I/O admission removes the dependence on timer scheduling
  for those admissions. It does nothing about I/O already admitted.
- "Half the remote timeout" is not inherently sound. A 40 s local deadline
  against a true 62 s remote boundary leaves ~22 s of budget before clock
  adjustments, and is sound only if the remaining worst-case terms fit inside it.
- What is not available is minting an unconditional handoff certificate first and
  relying on eventual local expiration afterwards.

The clock is part of the safety contract: monotonic, with understood behaviour
across suspend, VM pause and migration, and wall-clock adjustments must never
renew authority. Linux boottime accounting covers system suspend; it is not a
guarantee that a guest clock advances correctly through every hypervisor pause,
so that has to be tested and written down. Clock anomalies fail closed.

**If `Q` is unbounded, no finite timeout ratio completes the proof.** A software
check cannot retract a command already handed below it; a pause immediately after
the final check, or an indefinitely delayed transport retry, defeats an argument
resting only on the check's timestamp. Closing that needs exclusion that persists
despite the fencer's disappearance, a proven transport or target quiescence
mechanism, independent fencing against the old incarnation, or a handoff protocol
that keeps protection until quiescence is established. That is a limit of a local
software fix against a fail-open target — not a reason to keep detection-dependent
containment.

## 3. Where the gate goes

A VFS write check is insufficient. A transaction-entry check is insufficient. A
DLM acquisition check is insufficient. The media-safety gate belongs at the final
admission boundary for mutating I/O in the mount's ownership domain, as close to
block submission as practicable, and the audit has to cover:

| producer | paths |
|---|---|
| buffered data | writeback, reclaim writeback, delayed allocation |
| direct I/O | synchronous and asynchronous iomap/DIO submission |
| journal | iclog submission, CIL pushes, log forces |
| metadata | `xfs_buf` submission and delayed-write buffers |
| completion work | unwritten-extent conversion and other end-I/O metadata work |
| other mutations | zeroing, discard, write-zeroes, durability flushes and their ordering |
| coordination | heartbeat compare-and-write, disklock/page updates, raw LUN mutations |

**Coordination I/O matters most and bypasses the filesystem entirely.** An
expired heartbeat worker must not refresh its slot; an expired reservation-health
worker must not REGISTER, recreate a reservation, or preempt another incarnation
under its old authority. Re-admission is a separately authorised protocol, never a
generic "internal I/O" exemption.

Higher-level checks are still wanted — before accepting new modifying operations,
at fsync/commit success boundaries, and inside blocking waits so that expiration
produces an error instead of permanent sleep — but they do not replace the
low-level gate.

One genuinely universal, correctly synchronised choke point can be enough for
admission; what must not be assumed is that XFS already provides such a point for
all of the above. Deferred work has to retain its originating authority identity,
or work queued under epoch E is submitted under E+1 the moment it sees "mount
active". At final submission, check identity **and** deadline, and never relabel
old dirty buffers or queued requests as belonging to the new epoch.

"Already in flight" is a different problem and splits four ways: not yet admitted
(reject), deferred above the gate (recheck at the gate), already admitted below
the gate (account for it, drain or abort), retried below the gate (enforce there
too, or include the retry lifetime in the quiescence proof). Closing admission
should be atomic with respect to obtaining new permits, and old permits resolved
before handoff. A per-BIO epoch stamp is not magic — the target does not inspect
it — and a second check does not undo an earlier submission.

## 4. What the gate must not do

Do not perform the full withdrawal inside the submission check. The immediate
path atomically closes authority, refuses the operation, and arranges the
ordinary forced-shutdown processing. It must not require a PR read, a peer reply,
journal space, an allocation that can enter filesystem reclaim, or a lock that
withdrawal needs while waiting on this path. A short dedicated synchronisation
primitive is fine; the goal is no circular dependency with I/O completion or
shutdown, not the absence of synchronisation. Teardown is scheduled after
inappropriate filesystem locks are released, and the gate stays effective even if
teardown is delayed.

**It must be allowed to fail a log write.** An "essential journal write"
exemption reopens the hazard. This is an I/O-error and forced-shutdown path, not
a clean unmount, and it must not try to make the filesystem clean by issuing
final writes after ownership has expired. Rejected bios and buffers go through
correct error completion, releasing references and waking waiters — otherwise the
gate only converts writes into hung tasks.

Durable-but-unacknowledged work stays durable and stays uncertain to the caller.
No on-disk rollback is attempted from the expired incarnation; recovery
determines the committed state once old-epoch mutation has been excluded; late
successful completions must not restore authority or generate new old-epoch
metadata work.

Rejecting an fsync whose data was already durable is an acceptable false
negative, not a correctness violation. Returning success would also be defensible
if the whole operation were proven to have completed and linearised before the
loss of authority — but knowing that one data write completed is not that proof.
The simpler policy is to fail unacknowledged operations once shutdown is
observed, and to document that an error does not imply the absence of durable
effects.

## 5. The stalled metadata create, and the cost of a false positive

**The indefinite DLM wait is a second defect.** Not a media-corruption finding —
blocking does prevent that operation from mutating storage — but indefinite
blocking is not an acceptable withdrawal mechanism. Once local authority expires,
pending DLM requests must become locally abortable: mark the epoch failed, wake
the waiters, return an error, reject late grants and replies belonging to the
closed epoch, and require no acknowledgement from the dead peer. Journal grant
waits, log-force waits, buffer waits and teardown waits need the same audit.

**An otherwise healthy machine can lose its mount, and that is inherent in
timeout-based ownership.** A long scheduler stall, a VM pause, a heartbeat I/O
stall or severe overload can leave a node unable to prove continuing authority,
and it must then stop even though its data path still works. The cost is mount
withdrawal, uncertain results for outstanding operations, recovery and fresh
admission — and a complete outage if both nodes expire. Heartbeat recovery must
not silently reverse it. For availability the local interval must comfortably
exceed the supported heartbeat interval plus scheduling and completion delays;
for safety it must stay below the remote handoff boundary with the margins above.
If those two constraints do not overlap, the timing or the fencing architecture
has to change. Measured latency percentiles estimate how often withdrawal
happens; they are not hard safety bounds.

## 6. The evidence a fix owes

The existing lap becomes the first regression test and is not sufficient alone.

- **A. Exact reproduction with detection still suppressed.** B must close
  authority because of its *local deadline*, not because of PR inspection or a
  reservation conflict; the write and commit paths refuse; the DLM waiter is
  woken and fails; no prohibited old-epoch mutation reaches the LUN. Trace the
  deadline, the epoch, the closure reason and the final admissions — a withdrawal
  log line is not evidence of coverage.
- **B. The expiry machinery stalled too.** Park the expiry worker as well. The
  first resumed I/O must evaluate the time and close the epoch itself, or the fix
  is scheduling-dependent detection under a new name.
- **C. Heartbeat resurrection.** Worker resumes before the expiry worker; a
  completion is delivered after the previous deadline; the beat becomes
  target-visible long before its completion arrives; a beat succeeds after the
  reservation has gone; a health worker attempts re-registration or reservation
  repair. None may revive the old epoch.
- **D. Boundary and remote protocol.** Sweep the relative phases of renewal, peer
  sampling and death declaration; exercise stale reads and delayed death
  decisions; establish the earliest ACTUAL handoff boundary rather than the
  configured timeout; exercise every revocation path, not only heartbeat death.
- **E. Queue, retry and completion.** Inject delays before final admission, after
  admission but before lower-level submission, in block queues, in SCSI error
  handling and retry, in the transport, between data completion and unwritten
  conversion, and before delayed metadata and journal submissions — then fence,
  remove the reservation as early as possible, and release the delays. This is
  where a patch passes the current probe while leaving the original corruption
  mechanism reachable through old queued work.
- **F. Successor recovery and epoch reuse.** A successor replays the old slice
  while old deferred work and completions are released; the old incarnation must
  be unable to change the successor's recovered state. Nothing from epoch E may
  acquire E+1's authority.
- **G. Failure-path liveness.** Force expiration under dirty-memory pressure, log
  pressure, active DIO, reclaim, freeze/unmount activity and outstanding DLM
  requests. Shutdown must not depend on the writes the gate refuses, and error
  completions must release resources.
- **H. State the untestable assumptions.** Finite fault injection cannot prove a
  finite worst-case command lifetime. Completing a Linux request with an error is
  **not** proof that the corresponding remote command can never execute later.

## The bottom line, in its own words

> Implement the sticky local expiry gate. Anchor renewal conservatively, prevent
> every form of resurrection, cover coordination as well as filesystem writes,
> and propagate expiration into blocked DLM operations. But make release approval
> depend on the final property: before replay or new ownership is authorized, no
> old-epoch command remains capable of mutating the LUN — even after the last
> reservation disappears.

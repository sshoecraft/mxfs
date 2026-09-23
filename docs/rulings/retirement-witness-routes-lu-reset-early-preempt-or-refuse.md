# Three routes to a retirement witness, ranked

Design-consult ruling (Astra, session 82) on
`D-BOOT-SUCCESSION-CERTIFIES-FROM-IDENTITY-AND-ADMISSION-WITH-NO-TASK-RETIREMENT-WITNESS`
— the record that asks what may authorise replay when the victim's registration
is already gone. It continues
`retirement-proof-obligation-and-observed-transition-classes.md` and the LU-reset
analysis in `fence-ambiguous-drain-and-proof-resume.md`.

## The ruling

> The four probe laps do not qualify the absent-registration recovery path to
> this product's integrity standard. They support the observation reported, not
> a guarantee that registration disappearance retires previously accepted
> writes.

| route | judgement | what may be claimed today |
|---|---|---|
| **1. Witnessed LOGICAL UNIT RESET** | the best general solution, **if** it carries a target-response witness and safe local-I/O handling; it does not depend on the victim's registration surviving | **not** qualified merely because the Linux error handler returned success |
| **2. PREEMPT AND ABORT while the association still exists** | a sound conditional fast path, preferable when it works, not a complete recovery design | a measured 30 s window is not a guaranteed window; losing the race must be an explicit outcome |
| **3. Withdraw the qualification and refuse** | the required default wherever neither a real retirement operation nor an adequately supported target guarantee exists | **this is where the supplied evidence leaves the absent-association case today** |

**Implement 1 as the general mechanism, retain 2 as an optimisation, make 3 the
terminal fallback.** Falling back to the four-lap assertion leaves the original
defect intact.

Two qualifications on the product bar. No initiator can guarantee integrity
against a target that lies about command completion, reset completion, FUA or
atomicity; a protocol witness replaces an undocumented behavioural assumption
with reliance on a *defined* operation and the target's conformance to it, and
does not eliminate that reliance. And "no data loss" needs a durability
boundary: preserving acknowledged durable writes is a different promise from
preserving every in-flight write when a node is power-cut.

## What every successful route must establish

Not one successful command — four things:

1. **Admission exclusion** — the old owner cannot introduce additional
   conflicting work.
2. **Retirement** — previously accepted old-owner work cannot subsequently make
   stale logical modifications during recovery.
3. **Local-I/O control** — the survivor's own queued commands and retries
   cannot unexpectedly execute after recovery has started.
4. **Correct recovery and durability** — replay tolerates whatever partial
   effects existed before retirement.

Admission exclusion alone does not retire accepted work. Retirement alone does
not exclude later work. A reset does not make an interrupted write
transactional.

## Route 1 — the witnessed LU RESET

### The error handler's provenance is not disqualifying; its ambiguity is

The useful event is not "the ioctl, the handler or the EH returned success". It
is: *for this request, on this transport-session incarnation, the initiator
received and accepted a successful LOGICAL UNIT RESET task-management response
from the target, for the specified LU.* If the kernel can return the same
generic success after local session destruction or another recovery path, that
result cannot certify retirement.

Audit the exact deployed kernel and instrument where request and response are
associated. Retain, at minimum: stable target and LU identity (never `/dev/sdX`);
the actual requested function; the request's LUN and initiator task tag; session
and connection identity and incarnation, enough to reject stale responses and
tag reuse; receipt of the matching response with Function Complete; the fencing
epoch and admission-exclusion generation it was issued under; and confirmation
that the local operation was not abandoned, superseded or converted into a
different recovery outcome before the certificate was consumed.

A packet trace qualifies the mechanism; a production certificate needs the
corresponding trustworthy runtime event.

**Rejected as substitutes:** local session teardown or reconnection; a timeout
followed by successful device recovery; a reset-related unit attention; an EH
success reached through an unapproved escalation; a successful ordinary command
issued afterwards.

**Do not fabricate a command and call a low-level EH callback**: its locking,
recovery state, queue handling and calling-context assumptions matter. A
fence-specific task-management interface may be cleaner than extracting a
stronger meaning from an existing return value.

### Does it reach work whose session is gone?

Yes — that LU-wide scope is the point of this route. It is not "find the
victim's registration and abort its tasks", and the disappearance of the
originating session does not by itself exempt outstanding tasks for the LU.

Two boundaries: **task retirement is not media quiescence** — a command may have
completed with its data in a write-back cache, and later destaging is not a late
execution, so LU RESET is not a flush or a durability certificate. And an
implementation cannot use vanished task bookkeeping to justify later stale
logical writes; if accepted work can still execute conflicting modifications
after the reset's retirement boundary, that is a target-conformance problem, not
something registration retention would have fixed. Transport-deferred requests
that have not yet become LU tasks must be excluded by admission and protocol
ordering.

### The ordering

1. one recovery authority and one fencing epoch;
2. admission exclusion established and **continuously** effective — including
   against the victim's reconnects and its rebooted incarnation;
3. the survivor's ordinary submissions gated **at their producers** (filesystem
   writes, writeback, journal, outstanding block requests, deferred submissions,
   retries) — freezing a queue is not draining it; either drain to a known safe
   point or account for every local command the reset may abort;
4. issue the reset and require the matched target-response witness;
5. finish local reset handling **before** replay — no pre-reset survivor command
   may remain eligible for an uncontrolled retry against state replay has
   changed. A post-reset check cannot repair an exclusion gap *during* the
   reset: if the protection might disappear across it, another protection must
   span it;
6. recover under the same exclusion;
7. reopen ordinary submissions only after ownership and recovery are committed.

Refuse on any uncertainty in that chain. And note the operational bar: if an LU
reset's aborted commands make MXFS panic, force a shutdown or block
indefinitely, **this route has not met the bar even when the target-side
retirement was valid**.

## Route 2 — fence before the association is lost

Sound as a conditional path, unsound as a timing assumption. "We usually beat
30 s" and "the shortest purge we measured was 30 s" are not safety arguments;
four observations establish no minimum retention.

The rule must be: accept this path only when the PREEMPT AND ABORT itself, under
the applicable reservation semantics, establishes the victim scope and a
successful abort. The key must identify the relevant incarnation and its actual
nexus association; key reuse must not create an ABA problem; the reservation
type and service-action parameters must have the intended semantics; and **a
preceding PR IN snapshot is not an atomic capture of a later PR OUT's scope**.
Where a permitted success outcome would not establish that the matching
registration was found and acted on, GOOD alone is insufficient — that needs an
explicit case analysis for the actual reservation state, not a blanket reading.

Early abort with late death is not available: there is no two-phase "capture the
scope now, execute later". What *is* legitimate is separating **storage-ownership
revocation** from **declaring a machine dead** — suspicion revokes ownership
early, the possibly-live node must tolerate losing access without corrupting,
panicking or shutting down, and membership classification happens later. That is
early fencing under another name, and shortening a heartbeat timeout without
designing the live loser's behaviour is not it.

The fast path is worth having **only if losing leads to a safe outcome**: win →
scoped abort, lose → witnessed LU RESET, neither → refuse. If losing falls back
to the unsupported assertion, the integrity claim is still limited by that
assertion. Absent associations are not confined to whole-cluster restart —
delayed scheduling, recovery storms, session changes, target cleanup and
administrative action all land in that branch.

## Route 3 — withdraw and refuse

For absent-association recovery, refusal is the presently justified shipping
behaviour on this record. It does not mean everything stops; it means MXFS may
not authorise any recovery or ownership transition that needs the missing fact,
and "one node is still up" is not by itself permission for that node to continue
all shared-LUN writes.

The support statement must say that registration disappearance, an elapsed
interval and successful observation reads are **not** proof of retirement; that
the paths needing that proof are refused where no qualified witness exists; that
refusal is not evidence corruption occurred; and that operators must not
override it by waiting, rebooting an initiator, recreating a registration or
clearing reservation state. Publish firmware, kernel, target configuration, LU
identity and cache assumptions with the qualification — not just the model name.

The operator procedure must **establish** the missing fact, not ask the operator
to assert it: preserve the refusal record and diagnostics; prevent automatic
retries and competing recovery; establish a qualified target-side barrier (an
`SG_SCSI_RESET` success is not automatically stronger evidence because a human
invoked it, and an undocumented appliance reboot is not a barrier); preserve
acknowledged data (a power cycle may destroy volatile acknowledged writes);
re-establish ownership under continuous exclusion and recover exactly once;
readmit other nodes only afterwards. Where no approved barrier preserving the
required durability exists, remaining unavailable is the answer, and the
documentation should say so. Refusal must complete in bounded time with an
actionable error — "refusing" by hanging forever fails the operational bar.

## The fourth route, and what it is not

There is no ordinary SCSI command by which one initiator can ask "has all
outstanding work from this historical, possibly nonexistent nexus ended?" PR IN
reports reservation state; TEST UNIT READY, reads, FUA reads, COMPARE AND WRITE
and SYNCHRONIZE CACHE do not supply it — a cache synchronisation is not a
cross-nexus task-retirement barrier.

Three genuine alternatives, all needing a task-management path and a matched
completion witness:

- **CLEAR TASK SET**, where the LU has one shared task set covering the relevant
  nexuses and the target supports the function. With per-nexus task sets,
  clearing ours establishes nothing about the victim's.
- **A cross-nexus ordering barrier** (an ORDERED task), only if the tasks share a
  task set, the ordering rules cover all the victim tasks at issue, exclusion and
  transport ordering stop old requests becoming younger tasks, and the initiator
  actually emits the attribute and the target honours it. Worth designing
  separately; it can also stall behind exactly the work it must retire.
- **A broader reset or a documented target-management quiesce**, with explicit
  completion and persistence semantics. Losing the management connection during
  a reboot is not a witness.

## Shortcuts to prohibit in code and in the support statement

"no late rows" ⇒ "no outstanding work"; "registration absent" ⇒ "accepted
commands retired"; "session gone" ⇒ "the target stopped its work"; "EH returned
success" ⇒ "the target acknowledged this LU RESET"; "PR IN saw the key" ⇒ "the
later abort captured it"; "we normally beat 30 s" ⇒ "the association is
guaranteed"; "recreate the old key then abort it" ⇒ "the historical association
was restored"; "readback or flush succeeded" ⇒ "all other-nexus tasks ended";
"the reservation looks right afterwards" ⇒ "exclusion never had a gap"; "the
reset completed" ⇒ "no cache-persistence or partial-write problem remains";
"the operator clicked force" ⇒ "a missing storage fact became true".

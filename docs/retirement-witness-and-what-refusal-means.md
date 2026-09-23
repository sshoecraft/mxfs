# Task retirement, and what MXFS's refusal means

This is the support statement for the one recovery outcome an operator is most
likely to meet and least likely to expect: MXFS declines to recover a dead
node's journal slice, says so, and does not offer a way to make it proceed.

## The two halves of exclusion

Replaying another node's journal slice rewrites shared metadata. It is safe only
if two separate things are true of the dead incarnation:

**ADMISSION** — it cannot obtain permission for a NEW write. A SCSI-3
persistent reservation and the registration table establish this, and MXFS
proves it directly.

**RETIREMENT** — the target has finished with the commands it ALREADY ACCEPTED
from that incarnation's I_T nexus. Those commands passed their reservation check
when they were accepted; revoking the reservation afterwards does not recall
them. If one still executes, it lands under the replay as an unordered logical
write into metadata the replay is rewriting. That is silent corruption, not an
error return.

The two are independent. Admission does not retire accepted work; retirement
does not exclude later work.

## No initiator can observe retirement after the fact

There is no SCSI command by which one initiator asks "has all outstanding work
from this historical, possibly nonexistent nexus ended?" In particular, none of
the following is proof of retirement, and MXFS treats none of them as such:

- the victim's registration is no longer in the table;
- an interval has elapsed;
- reads of the volume return stable contents, or stop changing;
- SYNCHRONIZE CACHE, TEST UNIT READY, a FUA read or COMPARE AND WRITE succeeded;
- PERSISTENT RESERVE IN reports the reservation MXFS expects;
- the victim's iSCSI session is gone;
- the victim's host has rebooted.

A registration disappearing is not even a statement about *why* it disappeared:
the target does not report that. An iSCSI connection, an iSCSI session, a SCSI
I_T nexus and an MXFS boot identity are four identifiers with four different
lifetimes.

## What MXFS accepts as a basis

**A completed target operation whose own abort scope covered the victim's
tasks.** Today that means a PERSISTENT RESERVE OUT / PREEMPT AND ABORT that
named a registration still present on the target and completed. The abort scope
is the one the standard defines for that service action; it is a witness rather
than an assertion.

That is the whole list. A deployment assertion is not on it — see below. A
successful local error-handler return is not on it either: the useful event is
the initiator receiving a response matched to its own request, not a function
returning success.

**A LOGICAL UNIT RESET carrying a matched target response** would be the general
mechanism, because its scope covers the logical unit across its I_T nexuses and
so does not depend on the victim's registration surviving. MXFS cannot issue
one: every command it sends goes out as an ordinary CDB, and a task-management
function is not a CDB. Two further constraints apply whenever that route is
built: the reset destroys any other live initiator that has a command
outstanding to the LU — it is aborted at the target and never told, so it waits
on a completion that never arrives — and task retirement is not media
quiescence, so a reset is neither a flush nor a durability certificate. The
routes and what each would have to establish are ranked in
`rulings/retirement-witness-routes-lu-reset-early-preempt-or-refuse.md`.

## Why a deployment qualification is not accepted

Earlier versions let a deployment assert the ordering for its exact target,
firmware level and LUN designator, and certified when the assertion matched.
That is withdrawn, in code.

A clause of that shape is a conditional, and its premise is something no
initiator can establish. Worse, the module cannot detect a target that breaks
it: there is no error return, no refusal, no log line — only a replay that
quietly wrote over live metadata. And the assertion this project shipped rested
on four probe laps that observed no late write inside a 180 s window sampled at
50 ms. That characterises one appliance under one workload and one observation
interval. It cannot exclude a command the target retained without it ever
becoming observable, and more laps improve the characterisation without turning
an absence of observed late writes into an ordering guarantee.

A configured contract is therefore rejected out loud rather than ignored:
`P303-RETIRE-CONTRACT-REJECTED` names the value verbatim, so a deployment that
qualified its LUN learns that the qualification is no longer accepted instead of
inferring it from a refusal that never mentions it.

## What a refusal looks like, and what it is not

The recovery path that needs the missing fact refuses. Concretely:

- no certificate is minted, and no journal slice is replayed;
- the dead slice's grants stay frozen, and operations that need them fail fast
  with an error rather than waiting;
- the attempt is bounded: after a bounded series of non-proving attempts the
  slice is marked RECOVERY_BLOCKED, durably, and the state is readable at
  `/sys/kernel/debug/mxfs/<dev>/recovery_blocked`;
- a node that cannot have its predecessor's slice replayed does not complete its
  mount, and the mount returns a failure rather than hanging;
- a certificate of a kind that could only have been minted under the withdrawn
  qualification is refused where it is consumed, so an upgrade or a restart does
  not revive one.

**A refusal is not evidence that corruption occurred.** It is evidence that a
fact MXFS requires was not available. The data on the volume is whatever the
dead node had made durable; nothing has been replayed over it.

## What an operator must not do

None of the following makes the missing fact true, and none of them is
supported:

- waiting longer, or retrying the mount;
- rebooting an initiator, or power-cycling the node that died;
- removing or recreating a registration, or clearing reservation state, so that
  the absence looks like something else;
- re-registering a replacement key for the dead incarnation — a new registration
  does not identify the old nexus, and its presence retroactively proves nothing
  about the old one's work;
- forcing a replay, marking the journal clean, or skipping recovery;
- mounting read-only in the hope that recovery is skipped: a mount that requires
  recovery still requires it;
- asserting single-node exclusive access in order to get past the refusal.

There is deliberately no override flag. An override would reproduce exactly the
defect the withdrawal closed, with the operator's name on it.

## What an operator can do

Establish the missing fact, or restore from a copy.

- Preserve the refusal and the diagnostics before doing anything else; they name
  the victim, its incarnation, its key and the transition that was observed.
- Prevent competing recovery: do not let other nodes retry into the same state.
- If the deployment has a genuine target-side barrier with defined completion
  semantics — a documented management quiesce, a target-supported task
  management function issued by a mechanism that captures the target's response
  — that is the supported route, and it must be one that ESTABLISHES retirement,
  not one that asserts it. An undocumented appliance reboot is not a barrier,
  and a power cycle may destroy acknowledged writes still held in volatile
  cache.
- Otherwise the volume stays unavailable to that recovery, and a restore from a
  copy is the answer. Remaining unavailable is a supported outcome; replaying
  without the fact is not.

## What must be published with any future qualification

If a mechanism is ever qualified for a deployment, publish what it was qualified
against and not just a model name: target vendor, product and firmware revision;
the logical unit's designator; the initiator kernel and transport; the target
configuration and its cache settings; and the session topology. Changing any of
them withdraws the qualification rather than inheriting it.

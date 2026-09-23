<!-- sess576 Astra ruling on D-CLUSTER-FS-UNMOUNTABLE-AFTER-DEATH-REJOIN-0950: the per-boot PR key aliases successive incarnations on one nexus; serialize succession at the host/LUN fencing domain, rotate keys only after predecessor disposal, and never certify disappearance. -->
# Astra ruling — PR key / incarnation aliasing (sess576)

Question asked: the exclusion protocol reasons in incarnations (random nonzero 64-bit, frozen
into the victim's heartbeat record at death), but the PR key is derived per BOOT from
{host_uuid, boot_uuid, fs_uuid} (`dlm/prledger.c:128 mxfs_prledger_derive_key`), and the rig gives
one I_T nexus per host. Two successive incarnations on one host in one boot therefore carry the
same key, so a PREEMPT AND ABORT aimed at a dead incarnation lands on the live successor. Given
that a per-incarnation key on the same nexus destroys the fence target instead (absence proves
nothing), what is the right shape?

## The framing, restated

> A PR key must identify an exclusion domain whose ownership cannot change while a fence against
> that key remains possible.

MXFS changes the incarnation owning that domain while retaining the same hardware identity. The
frozen death snapshot preserves the *name* of the intended victim; it does not preserve the
hardware *meaning* of that name.

## The bind has an escape, and it was not in the question

One nexus cannot hold the predecessor's registration and a distinct successor key at the same
time. It **can** carry sequential incarnations safely if fencing and disposition of the
predecessor complete **before the successor registers**. That is the whole answer: serialize, then
rotate.

## CORRECTION TO THE RECORD'S OWN CLAIM

The record's mechanism section says the root chain was found. The ruling is that the causal
reading is **plausible but not established by the quoted logs**. "A mounted node lost its
registration" is equally consistent with a legitimate fence of the currently active incarnation
(including a false-positive death determination), a stale or wrongly authorized fence unrelated to
succession, an unregister on another path, or genuine PR-state loss.

To establish it, correlate the completed PR OUT with: issuer, action, RK, SARK, type/scope, status
and sense; the frozen victim incarnation and key; the affected host's active incarnation at that
instant; and the registration-to-transport-identity mapping. **READ KEYS does not say which nexus
holds a key — that needs READ FULL STATUS.** A PR generation number is not a compare-and-swap
condition on a later P&A.

Two further misreadings the logs invite:

- **"Retained" is not "present."** If the key was already gone, skipping the unregister preserved
  no fence target. `P302-PR-KEY-RETAINED-FENCE-TARGET` after self-registration loss is misleading
  unless backed by target verification.
- **`umount` rc=0 with `log_shutdown=1` is not a contradiction.** The detach completed; the slice
  did not become durably clean.

`P304-PREOBSERVE ... holder_key=0x0` under WE-AR is expected, not evidence of a foreign exclusive
holder. The later REGISTER conflict says only that this nexus did not hold the supplied RK —
cached knowledge of a selected key is not current registration ownership.

## What a correctly aimed P&A actually destroys

| object | effect |
|---|---|
| matching victim registrations | removed, with issuer-protection semantics |
| that nexus's outstanding tasks on the LU | aborted — successor reads too, not only the dead incarnation's journal writes |
| WE-AR registrant set | loses the removed registrations; remaining registrants keep write access (not a global RELEASE) |
| initiator / session / host | not killed, not permanently disabled |
| host-side queued work, future commands | **not** permanently excluded — re-registration makes retries eligible again |
| already-executed writes | not rolled back; an aborted command may already have had effects |
| the journal | untouched. P&A is not a cache flush and not a durability certificate |

Zero-SARK operations and reservation-type changes have broader semantics and must not be reachable
through a "fence this victim" helper.

## The four candidate shapes, attacked

**(a) Per-incarnation key + durable succession record — REFUTED as a proof.**
`REGISTER(RK=Kold, SARK=Knew)` explains the old key's *disappearance*. It does not establish that
old target-side commands were aborted, that old host-side commands cannot still be submitted, or
that a paused old operation cannot execute later. On one shared nexus the successor's registration
authorises **old software's I/O** exactly as readily as new software's — commands carry neither key
nor incarnation.

> "Kold absent because REGISTER replaced it" explains disappearance. It does not prove exclusion.

A succession record is still worth having, but as documentation of an independently established
exclusion event, binding: fs + LU identity and protocol generation; host/fencing-domain and
transport identities; old `{slot, node, incarnation, pr_key, key_gen}`; new incarnation/key;
transition id + recovery-owner epoch; state (intent / exclusion complete / replay complete /
predecessor disposed / successor admitted); the accepted exclusion kind and its evidence; and a
durable tombstone stopping stale recovery work from reopening the old victim. Note the threat is
not forgery — under WE-AR any registrant may overwrite the record, and **a stale authorised writer
can write a perfectly valid record containing an invalid causal assertion.** Signatures would
authenticate the author, not prove that old I/O stopped.

One hole survives every design here and per-boot keys do not close it either: P&A succeeds, the key
disappears, the recoverer dies before durably recording the proof. Absence is then unproven
forever. An intent record does not help.

**(b) A different SCSI primitive — DOES NOT EXIST.** PR access control is registration- and
nexus-based; it has no filesystem-incarnation concept. Task-abort mechanisms address known
outstanding tasks and do not prohibit future commands. A reset is broader, not more selective.
Changing reservation type adds no incarnation label to commands.

**(c) One nexus per incarnation — expressible, but a storage-stack redesign.** And only if the
target genuinely treats them as separate PR nexuses: **a second TCP connection is not a second
nexus** — connections may share one iSCSI session. Traps: I/O routing becomes part of the safety
proof (old work must stay bound to old paths and never fail over onto successor-authorised ones);
multipath aggregation by LU identity can silently merge old and new sessions and erase the
boundary; ALL_TG_PT / SPEC_I_PT / alternate controllers / failover paths all need explicit
treatment; shared bdev state, queued bios and delayed writeback must not cross the boundary;
session teardown must not drop the retained registration before exclusion is certified; orphan
registrations accumulate against target limits. It solves identity expressibility only — not
admission serialisation, and not sticky exclusion.

**(d) Honest host-granular fencing + serialised succession — THE RIGHT FOUNDATION for this
topology.** Define a host/LUN fencing domain and enforce: no successor registers or becomes active
until every predecessor obligation that could authorise fencing that domain is resolved — the
predecessor is durably clean and retired, **or** accepted exclusion completed and was durably
recorded; required replay/disposition finished; and outstanding fence operations, retries and
queued stale work can no longer fire against a newly assigned domain. That last clause is
load-bearing: a fence worker must not release its serialisation token while an async P&A or retry
can still execute. Checking the current slot immediately before submission does not protect the
check-to-completion interval.

This closes the observed aliasing hole *if* enforced before REGISTER and across every
fencing/succession path. The availability cost is real and must be accepted openly: same-boot
rejoin waits for predecessor recovery; unknown or orphan registration state can block the host;
proof lost after a successful fence can require an operator; a failed coordinator mid-transition
leaves a fail-closed domain.

## Registration-before-admission is a SEPARATE required defect

None of (a)–(d) fixes: peer P&A completes → old host re-registers → old host writes while the peer
replays. **A successful P&A is an exclusion event, not a durable ban on future registration.** So
the accepted-proof policy needs an invariant that preserves exclusion *through* recovery, or the
proof kind is insufficient end to end even though the SCSI operation behaved exactly as specified.

Required: split admission into a **pre-registration authorisation stage** (which cannot depend on
the joining node writing the ledger — use a currently admitted coordinator, an independent
authority, a target-side controller, or read-only discovery plus a serialised grant; a surviving
authorised node can write the transition record on the joiner's behalf) followed by the existing
durable on-LUN admission. Two distinct gates are needed: a **REGISTER gate** (who may issue a
registration-changing command, for which transition) and a **data-I/O gate** (no filesystem-
generated writes before admission despite SCSI write permission — covering delayed writeback,
replay, discard and alternate submission paths, not just VFS entry).

The transition owner's ordering:

```
close succession and registration authority
  -> prevent stale registration execution
  -> fence the present victim key
  -> persist accepted completion evidence
  -> replay and durably dispose of the predecessor
  -> authorise successor registration
  -> commit successor admission
  -> enable normal I/O
```

The transition authority must exist **before** journal recovery — a DLM resource whose own safe
recovery depends on completing this fence is circular. A timeout-expiring registration grant is not
enough: a paused thread or delayed PR OUT can execute an old REGISTER after the grant expired.

**Immediate, and it may be its own record:** remove any mounted-node repair path that automatically
re-registers after self-registration loss — that resurrects a fenced writer. Losing our own
registration must be **terminal** for that incarnation (one-way fenced/withdrawn, no automatic
reacquisition). Inspecting every five seconds while still presenting the mount as healthy is not an
adequate state machine.

## Is a lease + independent watchdog mandatory?

Not that specific mechanism, but **a persistent exclusion mechanism is mandatory** for safe
automatic recovery that makes progress despite paused or failed participants. PR alone does not
provide persistent exclusion against an initiator that can still REGISTER. Three viable forms:

- **Target-side persistent exclusion** (ACL / nexus disable): must stop access on every path,
  address existing sessions and commands rather than only future logins, prevent reconnection and
  re-registration under old authority, and hold until controlled rejoin. *Blocking new iSCSI logins
  while existing sessions continue is not fencing.*
- **Verified host fencing** (independent reset/power) plus a rejoin policy preventing unauthorised
  registration afterwards; P&A then covers the target-side outstanding-command and retained-key
  requirements.
- **Bounded lease with independent enforcement**: a lease authority that cannot issue overlapping
  ownership, explicit clock and delay bounds, a watchdog or I/O-disable that works while MXFS or
  the kernel path hangs, recovery waiting on the enforced deadline, no stale lease resurrection
  after resume or reboot, and control of delayed *registration* commands, not just data writes.
  *A heartbeat timeout plus a cooperative kernel timer is not an independent watchdog.*

A software-only fail-closed protocol preserves safety by refusing an uncertain transition forever.
That is safety without bounded automatic recovery. Note also that external fencing does not turn
key absence into a P&A-grade proof — preserve and P&A the registered key, use the operator
assertion as defined, or introduce a new proof kind through the protocol-change process.

## Recommended shape, in order

1. **Host/LUN-domain serialised succession.** Make dirty-predecessor refusal and stale-fence
   exclusion two sides of ONE state machine.
2. **Persistent exclusion / re-registration control.** Without it the recovery interval stays
   vulnerable whatever the key scheme.
3. **Per-incarnation keys, but only after predecessor disposal.** Never replace a retained dirty
   key. A stale fence against Kold then cannot remove a live registration using Knew.
4. **Separate retry identity from live-incarnation identity.** A pre-registration attempt can carry
   a durable pending identity so a crash-before-ledger retry resumes *that attempt* — which is what
   the per-boot derivation was bought for, and it does not require every incarnation in a boot to
   share a key.
5. **Treat PR observations as observations.** Distinguish: selected key / observed registration /
   own-nexus registration / completed fence / durable certificate.
6. **Lost registration is terminal for that incarnation.** No transparent resurrection.
7. **Preserve WE-AR across the migration** — nothing here needs a RELEASE→RESERVE gap; use the
   offline protocol-generation boundary for the incompatible admission semantics.

**Two nodes specifically:** define who may fence during a partition. A witness, an external
arbiter, or a deliberately availability-reducing policy is required to prevent competing recovery.
Quorum decides authority; it does not stop I/O, and the TCP transport does not change that.

## Test the interleavings, not the laps

Delayed P&A across successor admission; delayed REGISTER across fencing; crash after REGISTER
before the admission record; crash after a successful P&A before the durable proof; registration
loss while mounted; missing PR state after target disruption; every alternate-path and reconnect
case; competing recovery after a two-node partition.

## On the release bar

"Nothing may crash, hang or shut down a node" is a valid quality requirement. **"No node may ever
need to stop I/O, reset, or become unavailable under arbitrary failures" is incompatible with this
fencing problem.** Integrity here sometimes requires refusing admission, withdrawing a filesystem,
or externally fencing a host. The durability contract must also distinguish committed durable data
from un-fsynced writes on a failed node. That is a scoping question for the project owner, not a
disposition.

> Do not certify disappearance. Certify exclusion, preserve it through recovery, and serialise
> reassignment of the hardware identity. Per-incarnation keys improve identity hygiene; they do not
> replace those three obligations.

---
name: ccloop-c7ee71c6-sess93-GPT-ruling-fence-evidence-wiring
description: sess93 RULE-5 ruling on wiring the fence-evidence channel: one intent winner issues P&A, losers WAIT (never speculate), recovery_begin leaves the liv…
metadata:
  type: reference
tags: [sess93, GPT-ruling, RULE-5, fence-certificate, disklock, recovery, D-FENCED-STAGE-WITHOUT-PROVEN-EXCLUSION, D-VICTIM-REPLAY-WITHOUT-PROVEN-EXCLUSION, D-RECOVERY-TAKEOVER-UNREACHABLE, APTPL, binding]
---

# sess93 — the RULE-5 ruling that governs wiring the fence-evidence channel

Asked with the full sess92 inventory + the shipped API semantics + the sess73
rig measurements. This ruling is BINDING on the implementation; where it
conflicts with the sess74/75/76 design notes, this wins (it is later and it
saw the shipped code, not the design).

## Headline

> The current shipped flow is unsafe. The fence-evidence code is not merely
> unwired; **the live path contradicts its invariants.** Do not release
> recovery gating as a partial wiring change.

The release unit is SEVEN things, not one:
1. durable intent before fencing
2. durable certificate before replay
3. claim/takeover of the execution lease
4. authorization at every destructive operation
5. an explicit blocked-recovery state
6. removal / hard disabling of every ungated replay entry point
7. upgrade handling for old uncertified descriptors AND old binaries

## Q1 — single-winner: option (a), and option (b) is UNSOUND

Only the node that wins the `FENCING` intent CAS may issue the PREEMPT AND
ABORT. **One durable intent, one issuing prover, one command result, one
possible certificate.**

Why (b) — "let all 31 issue the P&A, only the winner certifies" — is wrong,
and this refutes my own proposal: *a loser can remove the key before the intent
owner issues its command. The intent owner then observes KEY_ABSENT_UNPROVEN
while the loser that actually got PREEMPT_ABORT_DONE is forbidden to certify.
You have converted a provable fence into an unrecoverable one.*

Per return code:
- `0` → this node ALONE issues the P&A.
- `-EEXIST` → **do NOT blindly treat as fenced.** Re-validate with a fresh
  full certificate check for the exact victim tuple.
- `-EBUSY` → issue NO P&A.
- `-ENOENT` → do NOT read generically as "safe": "sector zeroed / recovery
  already complete" and "no usable descriptor" are not interchangeable.
- anything else → no replay.

**An elected replayer that lost the intent** must enqueue onto a dedicated
recovery/coordinator workqueue and wait for: a valid certificate, a descriptor
state change, prover death, an explicit terminal fencing failure, or shutdown.
It must NOT replay speculatively, must NOT issue its own P&A while a live
attempt is owned, must NOT block the heartbeat thread, and must NOT infer
prover death from elapsed time. Poll 50-100 ms backing off to ~1 s.
**There is no safety timeout after which replay becomes allowed** — after
6 s / 30 s, change what the ADMIN SEES, not what is authorised
(`RECOVERY_WAIT_FENCE victim= victim_epoch= slot= prover= prover_epoch=
age_ms= reason=FENCE_ATTEMPT_IN_PROGRESS`).

If the certificate never appears, two DISTINCT cases:
- prover proved dead → the recovery coordinator (never the HB thread) runs
  `fence_takeover()`. Long term, change that API to a non-blocking
  "not abandoned until timestamp X" so the 6 s sleep becomes delayed work.
- **prover ALIVE but its result was non-proving** → `fence_takeover()` never
  applies. Leaving a live intent standing forever is NOT an adequate state
  machine: it makes UNSUPPORTED / KEY_ABSENT_UNPROVEN / timeout / hard SCSI
  error indistinguishable from "the live prover is still working." Needs
  retry under the same fauth, OR a durable `FENCE_BLOCKED` state that releases
  ownership while preserving the reason, OR explicit surrender.

### The crash hole GPT names as the LARGEST unaddressed issue

P&A succeeds → key removed → prover dies BEFORE `fence_certify` is durable →
takeover issues a new P&A → sees `KEY_ABSENT_UNPROVEN`. The proof existed only
in volatile memory and is lost. `fence_takeover()` does NOT solve this.
Failing closed is safe but it is a real availability hole that must be
documented and surfaced. **Do not claim takeover always repairs an abandoned
attempt.** Relaxing KEY_ABSENT_UNPROVEN is not a sound fix.

## Q2 — fail closed, and NO unsafe knob

For no-PR / UNSUPPORTED / ADVISORY_TOPOLOGY / NOT_REGISTERED / NO_RESERVATION /
VIEW_TRUNCATED / KEY_ABSENT_UNPROVEN: no foreign replay, no grant release, no
sector zeroing. *"The safe result of 'cannot distinguish dead from partitioned
writer' is loss of availability."*

But discovering it only after a death is not release-grade either: a clustered
RW mount must **validate at admission** that its fencing mechanism can actually
produce the evidence — PR available, reservation exactly WR_EX_RO, every
admitted writer registered, PR view complete, topology not advisory,
persistence present. tcm_loop rigs that cannot must be explicitly single-node,
read-only, or given a test fencing provider — never silently weaker.

A generic online `unsafe_recovery_without_fence=1` knob **is not acceptable
under a zero-known-defects bar.** Default-off + loud logging does not change
that. What IS acceptable is a DIFFERENT SOUND PRECONDITION recorded as an
external-fence certificate (power fencing, target ACL removal, exclusive LUN
presentation, offline repair) — that is a separate fencing authority, not
"unsafe replay".

Required: a durable, observable `RECOVERY_BLOCKED_FENCE` state exposing victim
node/slot/epoch, victim key, prover node/epoch, fence term, last SCSI result +
normalised reason, observed reservation type + PR generation, first-failure and
last-attempt timestamps, retry count, owner liveness, which locks/slice are
blocked, and the permitted admin actions. Mount status must SAY it is blocked
on unproven exclusion rather than appear hung.

## Q3 — zero incarnation: option (a)

The lease-only `(node, -1, 0)` event may mark suspicion/pending work but must
never create a certified guard, issue a victim-specific fence, authorise
replay, release grants, or zero a sector. **Do not weaken the nonzero-epoch
requirement.** The lease event should TRIGGER/ACCELERATE the disk heartbeat
detector, which produces the observed `(slot, victim_node, victim_epoch)`.

Option (b) — read the epoch off the victim's ACTIVE sector — is sound ONLY if
expanded into a real death observation: cache-piercing scan → find ACTIVE
record matching the lease-reported id → capture slot+epoch → **independently
observe that exact tuple fail the normal death criterion** → revalidate the
sector still names it before publishing intent. (That is just another
heartbeat monitor, which is fine.) A single read of a currently-ACTIVE sector
is NOT enough: it says what is present now, not that this incarnation stopped.

Never source the epoch from `node_track[slot].last_epoch`, current slot
ownership, or a successor's ACTIVE record. *Fabricating a plausible epoch is
worse than no recovery: it creates false authenticated evidence against a
potentially live successor.*

## Q4 — cross-boot victims and PR loss

62 s of absent heartbeats proves an omission during that interval, not that the
old host cannot resume. PR registrations vanishing after a target restart may
mean only that the target lost volatile PR state — so `KEY_ABSENT_UNPROVEN`
stays non-proving. Fail closed is correct, but a routine storage restart making
the FS operationally unrecoverable is not release-grade.

**MXFS should request AND VERIFY APTPL** — and not merely set the bit: at
mount/admission verify the target really persists registrations+reservation,
that the reservation stays WR_EX_RO, and reject clustered RW operation (or
require another fencing provider) if persistence is unavailable. Also needs a
stale-persistent-key cleanup policy, since node ids are random per mount —
tied to proved-dead incarnations, never removing current members.

A "cluster boot UUID changed" is NOT sufficient: ordinary XFS data writes are
not conditioned on an on-disk generation, so an old kernel with LUN access
ignores it. An on-disk epoch is a proof only if STORAGE enforces it.

## Corrections to my proposed wiring (all binding)

1. **Do not claim again in `recovery_complete()`.** Claim ONCE before replay
   and hold the auth across replay + completion; pass it through the work
   item/callback. Re-claiming makes ownership ambiguous and can mask lost
   context. Order:
   `claim → replay_authorized(auth,"replay-start") → replay (gated per
   destructive step) → replay_authorized(auth,"complete-start") →
   advance(IMAGES_REPLAYED,auth) → purge(auth) → flush →
   advance(GRANTS_RELEASED,auth) → zero sector(auth)`.
2. **Wire `recovery_takeover()`** — my proposal did not fix
   D-RECOVERY-TAKEOVER-UNREACHABLE. On `claim == -EBUSY`: owner alive → wait;
   owner PROVED DEAD → takeover; owner unknown → blocked. And prove foreign
   replay is safe to REPEAT after a prior owner died mid-write; if it is not
   idempotent at those crash points the execution-takeover design is
   incomplete.
3. **`recovery_begin()` must LEAVE the live path** — not kept as a fallback.
   Its `-EBUSY`-on-unowned behaviour is incompatible and its direct production
   of `FENCED/NONE` violates the protocol. Make it migration-only / unable to
   create FENCED / assert on `fence_kind==NONE`, and add a build or test check
   that no replay path references it.
4. **Authorisation must sit BELOW the dispatcher** — at or immediately above
   every destructive primitive (foreign log replay writes, replay-caused
   metadata writeback, authority/grant purge, stage transitions, final sector
   zeroing). A dispatcher-only check lets a future caller recreate the defect.
   Where practical make destructive APIs REQUIRE an `auth` parameter so an
   ungated call cannot compile.
5. **`-EEXIST` is a state-machine hint, not evidence.** Re-validate the full
   tuple through the fresh central gate before replay.

## Further release-blocking requirements (A-G)

- **A. Mixed-version safety.** A proto bump alone is insufficient if old and
  new nodes can mount together — old binaries still replay ungated and still
  create FENCED/NONE. Need offline all-node upgrade, a feature bit old builds
  refuse, mount-time negotiation that rejects unsafe members, or a format
  transition old binaries cannot write. **Existing uncertified FENCED/NONE
  records must be rejected or quarantined, never grandfathered.**
- **B. Anti-rejoin enforcement.** A successful P&A proves exclusion at a POINT
  IN TIME. Establish why the victim cannot re-register and resume writing
  during recovery (target ACL revocation, session fencing, mandatory
  self-fence on reservation loss, or a membership protocol that blocks
  registration until recovery completes, enforced BELOW ordinary FS writes).
  *If a partitioned old node can simply register its key again, the
  certificate is only historical evidence and is not enough to protect replay.*
- **C. Reservation health between certificate and final purge** — define what
  happens if the reservation disappears / changes type / becomes advisory
  after certification but before replay completes.
- **D. Durable ordering** must be proven and tested: intent before P&A;
  certificate before dispatch; replay writes before IMAGES_REPLAYED; purge
  before GRANTS_RELEASED; everything before the sector zero. CAW atomicity
  does not imply cache persistence across target power loss — FUA/flush must
  be explicit.
- **E. Exact-incarnation liveness** for BOTH takeovers: prove the owner
  INCARNATION dead, not that a node id or slot is absent.
- **F. Every non-proving fence result needs a defined state-machine action**
  (transient retry / wait / surrender / terminal block / external-fence
  request). "Leave intent standing" is not enough.
- **G. Crash matrix test** — inject death/power loss before intent persistence,
  after intent before P&A, during P&A, after P&A before certify, during
  certify, after certificate before claim, during replay, around every stage
  advance, during authority purge, around sector zeroing, during fence
  takeover, during execution takeover, and across target restart with and
  without APTPL. Assertions: "no foreign replay write occurred without a
  currently valid auth" and "no guard was zeroed without certified exclusion".

## Bottom line as stated

Two things must be explicitly accepted as fail-closed limitations or SOLVED
before claiming complete recovery safety: (1) the two-step protocol loses proof
if the prover dies after a successful P&A but before certification, and
(2) whether the P&A prevents a still-running victim from re-registering.

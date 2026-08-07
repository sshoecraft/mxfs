---
name: ccloop-c7ee71c6-sess68-GPT-ruling-takeover-evidence-REFUTED
description: sess68 GPT ruling: my takeover predicate REFUTED (sector non-residency is not fencing); slot_live is indexed by SLOT not incarnation (real bug); 4 mo…
metadata:
  type: reference
tags: [foreign-replay, recovery, coordinator, takeover, gpt-ruling, do-not-board, in-progress]
---

# sess68 — GPT ruling on the recovery coordinator's open design points

Build **0.11.411**, srcversion `93FB14589298C2E12BBAE2D`
(was `B9EDF45FFDC01DA13BA8EE9` at 0.11.410).  Clean build, no new warnings.
**STILL DO NOT BOARD** — 0.11.402..411 has never had a rig cycle.

This session asked GPT (RULE 5) to rule on the three points the sess66
ruling left open, BEFORE writing the coordinator.  It refuted the central
one.  Do not write the coordinator from the sess67 sketch — write it from
this.

## What landed in code this session (small, deliberate)

`dlm/disklock.h` + `dlm/disklock.c` — new
`mxfs_disklock_slot_holds_incarnation(ctx, slot, node, epoch, &read_ok)`:
cache-piercing single-sector read, true only for a well-formed ACTIVE
record of our fs_gen naming exactly `{node, epoch}`.  Fails CLOSED (true)
on unread sector, bad magic, alloc failure.  Its header comment carries
the refutation below so the next session cannot rebuild the wrong gate on
top of it.

It exists because `mxfs_disklock_find_node_slot()` CANNOT answer "is this
incarnation still resident" — its in-memory `slot_node_id[]` fast path
keeps resolving a dead node forever.

## RULING 1 — the takeover precondition I proposed is REFUTED

I proposed: takeover allowed when the sector at `d->owner_slot` no longer
carries `{owner_node, owner_epoch}` as ACTIVE, arguing that is strictly
stronger than "fenced" because the identity can never return.

**Wrong.**  `node_id` is an IDENTITY, not an I/O CAPABILITY.  The
descriptor CAS + `owner_term` protect DESCRIPTOR state; they do not stop
an already-accepted or in-flight SCSI command, nor a still-running replay
worker writing buffer images (those writes are not guarded by any auth
recheck).  Sequence GPT names: owner stops refreshing → its slot is
released/overwritten/zeroed → successor sees non-residency and takes over
→ old replay worker's write lands afterwards.

Sector state is admissible ONLY as *retirement evidence*, and only when
the transition that produced it has a documented ordering guarantee:

- `flags == 0` counts only if clean release is the FINAL act after
  (1) stop new recovery work, (2) cancel+join every replay/purge worker,
  (3) stop refresh, (4) drain/fence outstanding LUN I/O, (5) durably
  write flags == 0.  **That ordering is NOT established in this tree.**
- a zeroed sector counts only if zero-publication can happen exclusively
  after completed fencing AND recovery.
- slot reuse counts only if every claimable path derives from a properly
  ordered clean release or a completed fence.
- **bad magic / crc failure / unreadable is NEVER retirement evidence** —
  it is corruption/indeterminate; fail closed.
- `WITHDRAWN` counts only if its writer gives the same quiesce guarantee.
  "not ACTIVE" is far too broad.

Required predicate shape:

    owner != us
    AND the EXACT owner INCARNATION is not currently live
    AND authoritative retirement evidence for that incarnation
    AND descriptor unchanged for ABANDON_MS
    AND takeover CAS succeeds

Authoritative retirement evidence = one of: (1) a locally completed fence
for that exact incarnation; (2) a valid clean-retirement marker written
after quiescence+drain; (3) a successor state whose creation is
protocol-guaranteed to require (1) or (2).  `v5_node_is_dead()` qualifies
ONLY if insertion happens after fencing AND I/O exclusion complete — not
merely after declaring death.  Its 32-entry ring makes it incomplete but
not unsafe.

**If the existing formats cannot distinguish a valid clean/fenced
transition from corruption, the robust fix is a persistent retirement /
fencing TOMBSTONE (or a queryable fencing record).**  Do not interpret
"incarnation absent" as fencing.

Minimal extra gate before a takeover DISPATCHES replay: either the old
owner is session-fenced with old I/O drained, or replay application itself
rejects writes from an obsolete owner term.  An auth check immediately
before replay is not enough — TOCTOU, and it cannot revoke an accepted
write.

### A real bug this exposed in the sess67 sketch

`!mxfs_disklock_slot_live(d->owner_slot)` is **indexed by SLOT, not by
incarnation**.  Once the slot is reclaimed by a new live incarnation it
reads live again and takeover WEDGES FOREVER — and it is unconditionally
true for our own slot, so if we ever occupy the old owner's slot we can
never take over.  Monitor state may only be an advisory fast rejection
when it identifies the exact owner incarnation.

## RULING 2 — mount barrier may acquire, but ORDERING IS WRONG TODAY

Barrier acquisition is legitimate (it is replay-capable by construction).
But today's order — inline replay, THEN `recovery_complete()` does
`begin()` — is unacceptable: it replays before establishing exclusive
authority, so it can replay concurrently with an existing owner and only
discover the conflict afterwards.  Required order:

    read victim state → begin/adopt/takeover → register auth with the
    coordinator refresh table → start refreshing IMMEDIATELY → dispatch
    only the work implied by the recorded stage → recheck auth before
    each stage EFFECT and each transition → publish

**The hook-registration gate must suppress only ACQUISITION/DISPATCH — it
must NEVER suppress refresh of already-owned descriptors.**  And do not
rely on "the next 1 s pass will refresh it": register before starting a
long replay and issue an immediate refresh, or bound the remaining
abandonment margin explicitly.

Mount-failure relinquish: do NOT invent an abandon op and never move a
descriptor backwards.  Safe teardown order = stop acquisition → cancel+
join workers → guarantee no further FS or descriptor I/O → stop refresh →
drain LUN I/O / complete clean-session fencing → durably release the HB
slot LAST, as the retirement publication.  Clean unmount should prefer to
COMPLETE owned recoveries before releasing.

## RULING 3a — the all-slots backstop is right but incomplete

Scanning all 64 sectors every ~10 s and allowing only ADOPT/TAKEOVER (never
`begin()`) is a good rediscovery backstop and my reasoning for refusing
`begin()` there is correct.  But it leaves a REAL permanent hole:

    victim dies → every witness reboots before any begin() →
    victim sector stays stale ACTIVE forever → never recovered,
    and the slot is never reclaimable (claim scan refuses ACTIVE)

That needs a proper orphan-discovery path: find stale ACTIVE incarnations
→ establish death by a multi-sample/cluster protocol → elect/serialize a
fencer → fence the EXACT incarnation and drain old I/O → re-read → CAS
ACTIVE/WITHDRAWN→GUARD{FENCED} only if it still names that victim.
`lowest_live_slot()` may reduce duplicate fencing but is never the safety
proof.  If fencing cannot be reconstructed after all witnesses reboot, the
only safe behaviour is fail the mount/recovery and require administrative
fencing — silently treating stale ACTIVE as dead is unsafe.

Also: a scanner that merely SKIPS `-EPROTO` turns one damaged sector into
an unexplained permanent wedge.  It must quarantine / withdraw / enter an
explicit repair path.

## RULING 3b — resume STRICTLY from the recorded stage

My GRANTS_RELEASED handling is correct (no replay, no repeat purge, recheck
auth, CAS the exact observed image to the zero publication, clear local
pending only AFTER the zero is durable).  GPT extends it: **do not re-run
replay at IMAGES_REPLAYED either.**  Strict table:

| stage | next work |
|---|---|
| FENCED | replay images, make durable, advance |
| IMAGES_REPLAYED | obligations, make durable, advance |
| OBLIGATIONS_DONE | release/purge grants, make durable, advance |
| GRANTS_RELEASED | zero/publication tail only |

Unknown / regressing / invalid stage → fail closed.  A no-op obligations
step must be recorded explicitly, not left as an ambiguous stage jump.

## NEW FINDING — every stage is at-least-once (bigger than takeover)

The stage dispatcher avoids repeating a COMPLETED stage but not a crash
DURING one: owner at FENCED writes half the images and dies before
advancing; successor sees FENCED and replays again.  Same for obligations
and grant release — an effect can complete while its `advance()` does not.

So every stage effect needs one of: a durable idempotent/restartable
contract; durable per-item progress/claims; an atomic coupling of effect
and progress record; or device-enforced authority making duplicate
execution harmless.  Since we ruled that replay idempotence/LSN gating may
NOT be the contract, **one coarse IMAGES_REPLAYED stage is insufficient** —
this needs finer-grained durable replay progress, or a manifest op that
atomically claims/completes each image under the current authority.

## Other things GPT said it would refuse

1. Heartbeat absence as capability revocation (it is liveness publication,
   not write exclusion).
2. Clean slot release before worker quiescence + I/O drain.
3. Auth checks only around stage CHANGES — check before each externally
   visible EFFECT too.
4. **Plain zeroing without exact-image CAS.**  `mxfs_disklock_purge_node`
   is the publication today; a stale owner must not be able to zero a
   successor's descriptor.  AUDIT THIS — it may already be a shipped hole.
5. Clearing pending before the durable zero publication.
6. Slot-index liveness used as incarnation liveness (see ruling 1).
7. Bad magic / crc failure treated as owner absence.
8. Mount-path refresh gated on hook registration.
9. Advisory lowest-live election used as a safety or liveness proof.
10. Undefined `owner_term` / `stage_seq` overflow behaviour.

## Next session — revised implementation order

1. Decide the retirement-evidence mechanism (ruling 1).  Most likely a
   durable fencing TOMBSTONE, because none of the three admissible
   evidence forms exists in this tree today.  Consult GPT on the tombstone
   wire format before writing it.
2. Audit item 4 above (`purge_node` zero vs exact-image CAS) — it is a
   candidate SHIPPED defect, not just a design point.
3. Then the coordinator, with: refresh always-on (never hook-gated),
   acquisition hook-gated, strict stage resume table, incarnation-exact
   liveness, fail-closed -EPROTO.
4. Reorder the mount barrier to acquire BEFORE the inline replay.
5. Only then a rig cycle.

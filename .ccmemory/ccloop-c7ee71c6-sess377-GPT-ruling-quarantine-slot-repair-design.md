---
name: ccloop-c7ee71c6-sess377-GPT-ruling-quarantine-slot-repair-design
description: sess377 RULE-5 ruling for D-QUARANTINED-SLOT-EXHAUSTS-CLUSTER-ADMISSION-376: offline crash-safe chk_mxfs repair + slots 32..63 archive ledger + incom…
metadata:
  type: project
tags: [rule5, gpt-ruling, quarantine, disklock, chk_mxfs, defect-376]
---

«RULE-5 RULING — quarantined-slot exhaustion / operator repair path (sess377)»

Defect: D-QUARANTINED-SLOT-EXHAUSTS-CLUSTER-ADMISSION-376.
Consult: mcp__ask_gpt__query, gpt-5.6-sol, 2026-08-19.

## Central invariant the ruling sets

A quarantined slice remains UNASSIGNABLE until loss acceptance, slice
invalidation, required consistency repair, and durable verification have ALL
completed; only the final guarded transition may make it reusable.

## Chosen shape

1. Offline, exclusive, crash-resumable QUARANTINE-ACCEPTANCE repair operation in
   chk_mxfs. Name it for what it does: `chk_mxfs --accept-quarantine-loss <slice>`,
   NOT `--clear-slot`. Confirmation must carry a digest derived from the exact
   verdict so a generic "yes" cannot clear the wrong victim or filesystem.
2. Keep the source slot flags == RECOVERY_GUARD for the WHOLE repair, so every
   existing closure/admission gate keeps blocking. Repair phase lives in a
   versioned repair-state field inside the still-guarded record.
3. Archive the original verdict in a new on-disk ledger built on heartbeat
   records 32..63, gated by a superblock INCOMPAT feature bit.
4. Reinitialize the poisoned slice, run consistency repair, and clear the source
   slot only as the FINAL atomic generation-checked commit.
5. Fix the ENOSPC diagnostic immediately.
6. Headroom (shape a), guard relocation (shape b), and read-only admission
   (shape c) are NOT accepted as substitutes for the repair path.

At 32 slices a quarantined slice fundamentally leaves 31 usable RW journals.
Moving the heartbeat record cannot manufacture a 32nd usable journal. Shape (b)
is salvageable only as a REPRESENTATION change, never as a capacity fix.

## Q1 — may MXFS auto-clear a terminal quarantine?

NO, not if clearing abandons committed transactions. Automatic paths are allowed
ONLY where the committed transactions are PRESERVED: exclusion proof later
becomes available, a valid fencing result is re-established, another prover
supplies a durable proof, or the refusal turns out to have been transient. Then
the descriptor simply stays a guard until normal replay succeeds. Once the
resolution is "discard the unreplayable committed transactions" it needs explicit
administrative authorization — never an implicit kernel fallback.

## Q2 — repair semantics and ORDER (crash-safe state machine)

Domain: an AG-mask-limited repair is sound only with a proof that the quarantine
domain is CLOSED over every effect of the discarded transactions. XFS txns reach
the superblock and per-AG counters, inodes/dirs in other AGs, quota metadata,
free-space metadata, intent/done items, realtime metadata, and cross-AG deferred
ops. **Until that closure proof is implemented AND tested, treat every accepted
quarantine as FSWIDE.** Buffers observed in the log belonging to AGs {x,y} does
not make {x,y} the domain.

Exclusion: "every node unmounted" is necessary but NOT sufficient — absence of
fresh heartbeats is not proof of exclusion. The tool must acquire an exclusive
whole-volume maintenance lease/reservation, fence or exclude every registered
writer, hold it for the whole repair, refuse to run if it cannot prove
exclusivity, and additionally open the block device O_EXCL.

Order (each step durable before the next):
 1. Validate + DISPLAY: all CRCs and descriptor generations; print volume UUID,
    slice/slot, victim id, incarnation/epoch, PR key, fence kind, refusal
    reason, domain, digest. Require confirmation tied to that digest.
 2. Acquire exclusive maintenance ownership: fence/exclude all nodes, write and
    flush a durable maintenance owner/epoch. A second invocation must not race.
 3. Recover or settle all NON-quarantined slices. Ordinary log recovery must not
    inspect or replay the quarantined slice.
 4. Archive the original verdict to the ledger; flush; re-read and VERIFY. Do
    not touch the source guard yet.
 5. Record LOSS_ACCEPTED / SLICE_RESET_PENDING into the still-guarded source
    descriptor. This is the administrative point of no return; slice stays
    blocked.
 6. Reinitialize the journal slice with a NEW generation/incarnation so stale
    sectors of the old generation can never be recognized as log records. Do not
    rely on discard/TRIM. If the log format has no such generation, zero the
    complete slice, flush, then write clean headers with FUA/barriers. Record and
    flush SLICE_RESET_COMPLETE.
 7. Run consistency repair over the full proven domain (else whole-fs). Must be
    restartable. Finish with a CLEAN VERIFICATION pass — not merely a pass that
    reports it made repairs. Flush all repaired metadata.
 8. Record CHECK_COMPLETE / RELEASE_READY: checker version, scope, completion
    generation, result digest, archive reference. Flush and verify.
 9. Clear the source slot: ONE atomic generation-checked transition guard->EMPTY.
    Only this makes the slot/slice claimable. The archive remains.

After ANY crash the state must be one of: original quarantine still blocks; repair
in progress and slice still blocked; repair complete and source released with a
valid archive. There must be NO state where the slot is claimable before slice
reset and final verification are durable.

## Q3 — where the archive lives

Slots 32..63 as a recovery ARCHIVE LEDGER. They are physically present on every
supported volume, never claimable under the 32-slice hard cap, discoverable by
chk_mxfs and caw_slotdump, and outside the metadata being repaired.

New RECOVERY_ARCHIVED record must carry: fs UUID, source slot and slice, the
original raw descriptor (or its complete semantic contents), victim identity and
incarnation, refusal reason and domain, acceptance time, repair generation,
original-verdict digest, final repair-report digest, sequence number, CRC.

REQUIRES a superblock INCOMPAT feature bit: old kernels must refuse to mount, not
reinterpret a high-slot record under legacy monitor rules. The monitor must
distinguish legacy live/out-of-range occupants (fence/error) from active recovery
guards from archived non-live records (diagnostic only).

Capacity: only 32 archive records. Must NOT silently wrap or overwrite. When
full: refuse to finalize another repair until an operator exports and explicitly
prunes, or support explicit export with a retained hash-chain/checkpoint anchor
on disk. An external file plus zeroing the only on-disk evidence is NOT an
acceptable default. Rewriting the source slot as RECOVERY_ARCHIVED is unsuitable
— the next claimant necessarily overwrites it.

## Q4 — shape (b)

Salvageable as representation only. A relocated active guard in 32..63 could BE
the slice-quarantine marker if it contains slice=N and every admission/recovery
path scans those records before assigning a slice. But slice N stays unusable,
so only N-1 RW members can be admitted either way. Moving an ACTIVE guard adds
cross-record atomicity and compatibility complexity for no immediate benefit:
keep the source guard in place until final completion and use the high region for
the immutable ARCHIVE only.

**Adopted-slice mode must NEVER adopt a quarantined slice.** Suppressing the dead
incarnation's log images IS the destructive loss decision and cannot be an
incidental consequence of slot reuse.

## Q5 — degraded read-only admission

Not safe with the existing mount protocol. A nominally read-only MXFS mount may
still do log recovery, update mount/superblock state, write heartbeats,
participate in DLM membership and recovery, instantiate/tear down lock state,
update atime, or be handed a prover/coordinator role needing durable state. A
node holding ordinary DLM locks with no journal cannot safely perform any
transition whose recovery depends on durable log state. A sound observer role
needs: no log recovery, no metadata dirties on any path, no writable mmap/atime/
quota/lazy-metadata, shared locks only, no master/recovery-owner/purge/replay
role, no operation whose lock release implies a durable metadata transition,
quarantined-domain reads treated as unavailable or untrusted, and a
membership design that does not pretend the node owns a slice. That is a NEW
PROTOCOL ROLE, not a mount option — and it does not restore capacity. Must not
block the repair fix.

## Q6 — out-of-range occupants are a SEPARATE hazard (file it)

A valid-looking ACTIVE record at slot 40 on a 32-slice volume is an impossible
member. Scanning it is correct (ignoring it could leave a live writer unfenced),
but it must never be treated as an ordinary member. Required: never assign it a
slice or let it replay; validate CRC/node/incarnation/PR key; attempt exclusion
per the legacy protocol; report a format/protocol violation prominently; fail or
quarantine the mount if safety cannot be proved; never auto-clear it merely for
being out of range. Also test node-ID collision: a stale slot-40 record must not
cause the monitor to fence a CURRENT node when only the id was reused without
matching incarnation/epoch and PR identity.

## Q7 — the closure test matrix (A-H)

A. Reproduce at max capacity: mkfs -n 32, 32 nodes, commit txns then withhold
   home writes, kill victim N, make its PR key unreprovable, force terminal
   refusal. Assert: exactly one durable GUARD for slice N; reason/victim/
   incarnation/PR key/domain survive reboot; nobody replays or adopts slice N;
   31 usable RW slices not 32; the 32nd claimant gets an accurate error naming
   the quarantined slice/verdict count; the message does NOT recommend -n 33;
   closure gates enforced on every node.
B. Authorization + exclusion: attempt repair with a healthy node mounted, with a
   stale node still holding a PR registration, with a node resuming I/O after
   heartbeat timeout, with two repair tools racing, and with a digest for a
   DIFFERENT verdict. All must fail BEFORE altering the slice — capture device
   writes to prove the rejection paths modified nothing.
C. Exhaustive crash matrix: kill after every durable transition and where
   possible every individual sector write (ownership, archive write, archive
   flush, archive verify, loss-accepted, partial slice zero, clean-header write,
   each checker batch, checker flush, check-complete, final clear CAS). After
   each restart assert the slice is never prematurely claimable, poisoned records
   are never replayed, repair resumes deterministically, a partially reset slice
   reads as reset-in-progress (not as a valid old OR new log), source guard and
   archive cannot both disappear, release only after a clean verification pass.
   Use torn-write and reordered-flush injection, not just clean process kill.
D. Lost-log consistency: discarded committed txns covering inode alloc/free,
   extent alloc/free, dir add/remove/rename, orphan/unlinked handling, quota,
   deferred intents and dones, AG free-space and inode counters, cross-AG
   rename/alloc, superblock/global counters, realtime if supported. After repair:
   checker clean on a SECOND full pass; no multiply-allocated block; no freed
   block reachable; no reachable inode references free metadata; counters agree
   or were intentionally rebuilt; no stale intent executed from the reset slice;
   user-visible loss REPORTED, not characterized as lossless repair. These cases
   are also the AG-domain-closure proof — if any txn escapes the recorded AG set,
   disable domain-limited repair and require FSWIDE.
E. Admission race: race a claimant against the final source clear. It must see
   either the guard (fail admission) or the fully completed clean new slice
   generation (succeed) — never an empty slot with an incomplete reset/check.
F. Archive: survives source slot reuse; found by fs UUID + source slice from
   chk_mxfs and caw_slotdump; CRC corruption detected; exhaustion refuses silent
   overwrite; export/prune preserves a verifiable digest chain; old kernels
   reject the incompat bit; upgraded monitors do not fence archived identities.
G. Out-of-range occupants: plant valid-CRC records at slot 40 on an N=32 volume
   for ACTIVE / WITHDRAWN / RECOVERY_GUARD / RECOVERY_ARCHIVED, with stale and
   current node ids at differing epochs. Assert fencing, refusal, diagnostic and
   compatibility behavior. No out-of-range occupant may acquire or imply a slice.
H. Report: usable RW slice count before/during/after; number and identity of
   quarantined slices; exact domain scanned; metadata objects/blocks checked and
   repaired; archive sequence and digest; journal generations before/after reset;
   real flush/FUA ordering from block traces; max repair and whole-fs scan time;
   behavior with one vs several simultaneous quarantines; behavior with a full
   archive ledger.

## Patch split (ruling's own order)

1. NOW: correct the ENOSPC diagnostic; count and report guards.
2. CRITICAL: offline crash-safe repair with exclusive fencing and final-clear
   ordering.
3. SAME FORMAT CHANGE: high-slot archive ledger + incompat feature.
4. HARDENING: classify out-of-range active occupants as protocol violations.
5. LATER/OPTIONAL: a true observer-only mount role.
6. NOT ACCEPTED AS A FIX: headroom, or guard relocation without a repair path.

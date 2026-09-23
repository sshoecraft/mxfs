<!-- sess404 RULE-5 ruling: fence-time manifest SNAPSHOT = S2 (durable sealed manifest in a per-victim region) + protected-projection validation + expande… -->
# sess404 GPT ruling — fence-time manifest snapshot design (D-FOREIGN-REPLAY-UNGATED-IMAGES owed item, stop-ship gate for enforcement default-on)

## Context given
Live slot read at verdict (victim bit + ex_grant_epoch + lineage) is immutable by audit between
fence and purge, but sess402 required a fence-time SNAPSHOT. HB record is fully packed (no bytes);
envelope has a dormant legacy DLM journal region (64 x 1 MB, claim/release only in CAW path);
held-at-death set can be tens of thousands of slots; full table walk = 32 MB.

## Decision: S2 AUTHORITATIVE
- Replay verdict derives ONLY from a durable, sealed fence-time manifest; live slot reads are for
  current-safety/invariant checks, never historical authority.
- S1 (crc/xxhash digest in the descriptor + verified live read) NOT acceptable as sole authority
  (error-detection hashes are not binding commitments; no durable diff after crash; generation
  changes from unrelated PR/open updates cause false failures). Keep only as audit.
- S4 (writer-side guard) = required defense-in-depth, broadened: centralized checked CAS API;
  refuse clearing EX/PW, epoch/lineage change, rebind, conflicting grant, repair/admin rewrite,
  closure strip, legacy paths on a victim's resources from durable SNAPSHOT_IN_PROGRESS through
  durable replay/closure; purge exception narrowly scoped to the elected owner + current term;
  keyed by victim slot AND incarnation, fence term, snapshot seq.

## Ordering (required)
detect HB expiry -> prove fence -> durably establish recovery ownership/incarnation/term ->
durable SNAPSHOT_IN_PROGRESS (protection starts here, NOT at FENCED) -> block conflicting
strip/grant/rebind/repair -> scan (bulk I/O, bounded generous timeout, telemetry; fail closed on
error, never fall back to live authority) -> write manifest -> flush+seal -> publish FENCED
descriptor pointing to that exact sealed manifest -> classify/replay -> durably record
completion -> purge -> release protection. Manifest retained through purge + closure.

## Manifest contents
Per held entry: slot_idx, resource type/key or strong lineage, held mode (EX/PW), the grant
epoch for that mode, victim incarnation binding; generation optional (diagnostic only — never
let unrelated generation bumps invalidate authority; never treat generation as grant identity).
PR-only / open_holders are NOT write authority — never satisfy APPLY; snapshot them separately
only if closure/purge/rebind predicates need them. Header: format/version+feature id, victim
slot, incarnation, fence term, snapshot seq, entry count, exact length, checksum/digest, seal.
Canonical, domain-separated serialization. Multi-token txns validate against ONE manifest.

## Post-seal mutation of a protected slot
= broken recovery invariant -> STOP replay for the whole slice/attempt, do not purge, preserve
manifest + current image, identify/fence the offender, require explicit re-decision. Never skip
just the transaction. Corrupt/torn/truncated manifest or pointer mismatch = fail whole attempt.

## Stop-ship hazards
1. 1 MB legacy slot vs protocol MAX 65536 entries (x24 B = 1.5 MB): prove worst-case capacity
   (packed format) OR enforce a hard pre-grant cap below capacity OR reserve more slots OR a new
   region (layout migration). Typical counts are not a bound.
2. No durable protection during snapshot construction (FENCED-only guard leaves a gap).
3. Repurposed journal region needs an on-disk feature/version gate + mixed-version exclusion,
   and proof no legacy recovery state is destroyed.
4. Manifest + seal durable BEFORE the descriptor pointer is authoritative; never overwrite
   early.
5. S2 without current-safety validation (snapshot proves history, not that no concurrent
   regrant happened after the seal).

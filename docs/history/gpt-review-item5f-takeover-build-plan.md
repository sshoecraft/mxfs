<!-- sess443 RULE-5 review of the 5f takeover BUILD PLAN: 8 STOP-SHIPs (REGISTER before election under WE-AR, PREPARED must inspect K, fence stale contend… -->
# sess443 RULE-5 review — item 5f (bootstrap takeover) implementation plan

Plan reviewed: 32 KiB region {s0 record, s1-15 manifest bank A, s16-30 bank B (term parity), s31 TAKEOVER, s32-39 receipts, s40-47 lineage}; contender election on the TAKEOVER sector; fence old owner (on K if K_CLAIMED, else slotless); build T+1 manifest with inherited-complete class 6 + fenced-owner class 5; lineage entry = T's escrow verbatim; composite K replay = array of (desc, manifest) pairs selected by token incarnation.

## STOP-SHIPs
1. **REGISTER before the election.** Under WE-AR a non-registrant cannot CAW the TAKEOVER sector. Order: REGISTER (ledger entry) → election CAW. Losers unregister their own key; a dead loser's key is a class-3 registration the eventual owner fences.
2. **PREPARED does not prove K unadopted** (crash between the K claim CAW and escrow K_CLAIMED). For PREPARED: read K against the escrowed guarded image — still the victim guard ⇒ owner slotless; ACTIVE|PENDING for O ⇒ treat as K_CLAIMED (fence O through a new K descriptor + snapshot); any third image ⇒ terminal. K_REPLAY_REFUSED stays terminal (never becomes a takeover replay).
3. **A stale contender must be FENCED (P&A) and put in dead_incarnations before any recovery mutation** — its TAKEOVER heartbeat failing later does not stop an in-flight descriptor CAW / manifest write / record CAS. If it created K's takeover descriptor, the successor fences it, marks the exact tuple dead, then recovery_takeover on that descriptor. The TAKEOVER sector must keep the predecessor contender's identity (never overwrite it away).
4. **TAKEOVER sector = durable staged journal**: CONTENDER → OLD_FENCE_INTENT → OLD_FENCE_DONE → K_DESCRIPTOR_DONE → CAPSULE_WRITTEN → RECORD_COMMITTED; binds target record identity (term+nonce+owner tuple+key), contender tuple/key, stale-predecessor tuple/key, fence kind, PR generation, K descriptor crc. Write *_FENCE_INTENT before every P&A (a successor must distinguish "fenced then crashed" from "key vanished").
5. **CLAIMED is not importable**: no sealed manifest. CLAIMED ⇒ fence the owner, then the ordinary fresh scan/claim flow for T+1. MANIFEST_SEALED ⇒ import manifest, no completed inheritance. RECOVERING ⇒ import manifest + completion proofs + escrow/K state. Never validate an unsealed bank.
6. **Completion proofs must survive a second takeover**: a bit inherited at T+1 has only a T receipt. Make receipts term-INDEPENDENT tombstones keyed by {victim incarnation, slot, obligation}, with kind DIRECT | INHERITED (+ source proof hash); every manifest refers to them; before committing T+1 write an INHERITED proof for every copied bit (never claim T+1 replayed).
7. **Packed receipts need exact-image CAW on the whole 512-byte sector** (8 per sector; concurrent completion workers, torn RMW).
8. **Geometry**: growing 8→32 KiB is safe only if the super carries the region size and old kernels refuse before writing (PROTO_GEN gate). MXFS super has bootstrap_offset/size → OK, but mkfs must write 32 KiB and the kernel must refuse size < required.

## Composite K replay + live check — RULED
Latest pair checked against K's CURRENT CAW bits; older pairs by their immutable manifest+certificate only. Valid only if: every hop i→i+1 carried a P&A of incarnation i; the manifest was snapshotted after that P&A; the certificate binds descriptor+manifest+slot+victim tuple; the next engine could not start before that was durable; lineage is an unbroken chain for the same K; old RMAN storage immutable until the episode retires; epochs never reused. Token selection by {node, epoch, slot}. **The new owner's grant engine must stay frozen until K own-log replay + shadow eval complete** (else the owner mutates the bits its own live check reads — this is the chain-29 P-RMAN-POSTSEAL-MUTATION risk). O-tokens accepted only if T's final escrow ∈ {K_CLAIMED, K_REPLAY_OK} (never from PREPARED even if the adoption CAW landed).

## Ordering (16 steps)
1 REGISTER key + ledger → 2 TAKEOVER exact-image CAW → 3 if replacing a contender: fence intent, P&A its key, certificate, dead_incarnations → 4 old-owner fence INTENT durable → 5 fence old owner (K descriptor if K might be adopted; else slotless P&A + TAKEOVER-sector certificate) → 6 fence DONE durable → 7 re-read record → 8 require unchanged owner/term/state/nonce/manifest identity (seq may have advanced pre-P&A; use the post-fence image as the CAS expected image) → 9 take over any descriptor an earlier contender left → 10 write new manifest bank → 11 write/reissue every inherited completion proof → 12 lineage entry → 13 revalidate TAKEOVER ownership → 14 CAS record → T+1 → 15 record heartbeat → 16 clear TAKEOVER by exact-image CAW only if it still names us.
Crash at each boundary is recoverable (orphan manifest/lineage ignored: no record references them).

## Class 6 (inherited complete)
No re-replay if the guard at GRANTS_RELEASED validates (order replay→purge→flush→stage durable). Still-guarded ⇒ fence the descriptor owner, exact-image CAW zero (or takeover + normal tail). Already zero ⇒ tombstone.

## Paused old owner
After P&A completes, O's CAWs (record heartbeat included) are rejected by the target — O cannot alter the record between P&A and our CAS. Before P&A O may bump seq: re-read after P&A. Self-succession branch: ledger binding alone is NOT an I/O-abort certificate; safe only if transport teardown aborted all old-boot I/O and the key is on no other nexus/path.

## Layout ruling
Keep two banks + lineage + receipts with: staged TAKEOVER journal; term-independent proofs; CAW receipt sectors; stale-contender identity kept; reset lineage/receipt episode on IDLE→CLAIM; refuse term wrap; geometry in the super.

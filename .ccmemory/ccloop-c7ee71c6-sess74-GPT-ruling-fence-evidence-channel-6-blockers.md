---
name: ccloop-c7ee71c6-sess74-GPT-ruling-fence-evidence-channel-6-blockers
description: sess74 RULE-5 ruling: unowned victim-sector fence certificate APPROVED as architecture, with 6 release-blocking requirements — plus my mixed-version…
metadata:
  type: reference
tags: [scsipr, fencing, recovery-descriptor, gpt-ruling, design, wire-format]
---

# sess74 — GPT RULE-5 ruling on the fence-evidence channel

Design put to GPT: descriptor **v2** carrying a fence certificate, published by
the PROVER into the VICTIM's own HB sector at fence time, **UNOWNED**
(owner_node/epoch/term = 0), later **CLAIMED** by the elected replayer; replay
gated on `mxfs_fence_kind_proves_exclusion(desc->fence_kind)`.

## VERDICT: architecture APPROVED, implementation NOT yet approved

> "Proceed with the victim-sector, certified, initially-unowned descriptor
> architecture. Do not proceed with only the proposed post-P&A publication path."

**Q1 YES.** Both alternatives were rejected correctly: the prover's OWN sector
loses the evidence when the prover dies (the certificate belongs to the victim
recovery TRANSACTION); prover-owns-and-replays couples two separate roles, adds
failover latency, fights the election architecture, and does not fix the
publication window anyway.

**"Claiming an unowned recovery lease is not takeover" is RATIFIED as a
legitimate extension to disklock.h rule 5.** UNOWNED must be a DISTINCT state,
never "an abandoned owner". `owner_node == 0` must be impossible for a real
node. Claim must CAS the WHOLE descriptor while validating the immutable
certificate bytes, and establish owner_term 1 atomically.

## SIX RELEASE-BLOCKING REQUIREMENTS

1. **Durable FENCING intent**, written BEFORE the P&A is issued.
2. **An authoritative fallback for the P&A-result-loss window.**
3. **Refuse RW clustered operation on unqualified PR/topology** — not a knob.
4. **Centralised replay AND stage-transition enforcement.**
5. **Cluster-wide version gating.**
6. **Complete audit of every ACTIVE / non-ACTIVE consumer.**

## Q2 — the lost-prover window: my mitigation is NECESSARY BUT NOT SUFFICIENT

The interleaving is confirmed real and MUST-FIX (not operator quarantine):
P&A completes at the target → prover dies before the certificate is durable →
victim key absent forever → no successor can ever prove exclusion → that slice
is permanently unreplayable.

An intent record is worth landing, and it does buy: serialising fence attempts,
preserving the exact victim key + pre-command observations, and distinguishing
"fencing never started" from "fencing result uncertain". But this inference
remains **UNSOUND**:

> intent exists + prover died + victim key absent ⇒ the intended P&A completed

That depends on target-specific registration-removal semantics (the sess73 SCST
source finding is good RIG evidence, not a portable proof). The only sound
general recovery is to **perform a NEW accepted exclusion/drain operation and
certify THAT operation**. Where no such fallback exists, permanent quarantine is
the only safe result.

Required protocol: durable FENCING intent → acquire a fencing-ATTEMPT lease/term
(separate from the recovery-EXECUTION lease) → P&A + verify → atomically advance
to certified FENCED and release ownership as UNOWNED. On actor death: fence the
actor, take over the fencing-attempt lease, re-P&A if the key is still present,
else run an authoritative fallback drain/reset and certify that.

**PROHIBITED — ruled fabricated evidence:** re-registering the victim's numeric
key on our own nexus and then preempting it. "PR keys are not identities or
capabilities"; that proves only that we removed our own fabricated registration.
**PR OUT CLEAR is not a substitute** either (disruptive, no task-set drain, can
leave the LU writable without the reservation). LU reset counts only if its
completion semantics satisfy the drain proof AND the victim cannot resume; a
reset is a drain, not a persistent fence. Target session drain counts if the
management plane identifies the actual victim nexus and durably acknowledges it.

## Q3 — PR-incapable / nexus-collapsed rigs: ruling is (a), generalised

UNSUPPORTED and ADVISORY_TOPOLOGY may **not** be classified as fenced. On the
shared-nexus topology the PR identity model is defeated outright: registrations
belong to target-visible nexuses, not MXFS node ids, so one VM's REGISTER can
overwrite another's and a dead VM can keep writing through a nexus still
registered under someone else's key — removing the victim's nominal key excludes
nobody. Lease expiry + write-error shutdown do NOT repair it: "a timeout is a
suspicion, not a proof"; reactive shutdown happens only AFTER an I/O fails, so
the unsafe writer can complete writes first.

Required: refuse RW clustered mount unless the deployment supplies at least one
positively-qualified durable exclusion mechanism (per-node PR, per-node target
sessions with management-plane drain, NPIV-style unique initiator identities,
or hypervisor power fencing with durable ack). Optionally allow an explicitly
safe RO/diagnostic mode. No bypass knob may reach RW recovery.

A one-time mount probe is NOT sufficient, and `key_count >= live_members` stays
refuted. Need runtime detection of lost registrations, reservation changes, path
migration and nexus collapse, with fail-closed withdrawal.

## Q4 — gate placement: my two call sites are NOT enough

Authoritative gate must sit (1) inside/immediately below
`recover_foreign_slice()` before the first replay I/O, (2) on the transition to
IMAGES_REPLAYED, (3) on every path that begins destructive victim-manifest work,
and (4) on sector zeroing / final publication. Call-site gates remain useful as
defence in depth. Election SHOULD also require the certificate — always-elect-
then-refuse is not inherently unsafe but risks accidentally creating ownership
or advancing state before authorisation.

Validation must check ALL of: version exactly supported, crc, record identity
triple, victim_node, victim_epoch, victim_fs_gen, victim_slot, slice_idx,
slice_count, nonzero recovery_gen, CERTIFIED stage (not intent), exact accepted
fence_kind, required reservation type+scope, victim-key binding, immutable
certificate fields, and the owner tuple after claim. Not "a v2 descriptor exists
and fence_kind is in a set".

**Mount barrier specifically:** re-arm-retry is sufficient ONLY if the mount
stays blocked / the FS stays unavailable. It must not go RW with a slice
unreplayed.

## MY CLAIM REFUTED — mixed-version is NOT automatically fail-closed

I argued "a v1 reader sees version != 1, returns NULL, callers refuse to touch
the slot". **Wrong**, and the reason is in the shipped ordering I had already
read: today's replayer REPLAYS FIRST and calls `recovery_begin()` only at
completion. So a v1 node can be elected, replay the foreign slice on the old
path, and only afterwards meet the descriptor conflict — exactly the operation
the gate exists to prevent. Per-slot fail-closed is not a substitute for
cluster-wide protocol compatibility: gate v2 through the existing sess42 C7
version-gate feature block and exclude v1 recovery code from the cluster.

## Rule amendments demanded (disklock.h rules 1-6)

- Rule 1: an intent is NOT FENCED; only a CERTIFIED FENCED descriptor permits
  post-fence operations.
- Rule 3: "victim fenced" must require a VALIDATED CERTIFICATE, not merely
  GUARD + descriptor naming the victim. An intent must not authorise replay,
  purge, manifest repair/reuse, grants release, broadcast or zeroing.
- Rule 4: the manifest freeze should begin at FENCING, not at certified FENCED.
- Rule 5: add the UNOWNED claim transition + a separate fencing-attempt takeover.
- Keep the two leases (fencing-attempt authority vs recovery-execution
  authority) semantically separate even if encoded in one descriptor.

## Certificate content notes

`fence_pr_gen` is diagnostic only — a wrapping counter that unrelated PR ops
also move; it is NOT a transaction id. The victim key must be unambiguously
derived/validated against {fs_gen, victim_node, victim_epoch} or a stale event
can certify removal of a recycled numeric key from a different incarnation. Bind
target/LU identity (or an invariant tying the sector to the same PR domain),
reservation type+scope, prover identity+incarnation, the exact successful
service action, and the post-state observation. Durability needs FUA/flush plus
a validating re-read, not command completion into a volatile target cache.

## MY OWN CODE AUDIT THIS SESSION (verified, feeds requirement 6)

Publishing GUARD at fence time instead of completion time:
- `hb_still_dead_stamp()` — **SAFE**. A GUARD record keeps node_id+epoch
  (rule 2), so the victim-stamp branch already returns true, and
  `recov_lease_covers()` is the backstop. Early GUARD does NOT trip the
  "recovery complete" broadcast that releases peers' deferred purges.
- `mxfs_disklock_claim_slot()` pass 2 — **SAFE**, explicitly skips
  RECOVERY_GUARD (disklock.c ~3002).
- HB monitor (~676) — **SAFE**. non-ACTIVE on a monitored slot does
  `equal_samples++; goto check_dead`, and check_dead's "NOT evicting" confirm
  requires flags == ACTIVE, so a GUARD sector evicts. Correct direction.
- `mxfs_disklock_find_node_slot()` — **SAFE**, has a `recov_desc_names()` arm.
- `mxfs_disklock_get_slot_node_id()` (disklock.c ~2904) — **HAZARD**, returns 0
  for any non-ACTIVE record. This is exactly GPT's item 6: do not overload
  "non-ACTIVE" as "no node identity". Needs a descriptor-aware resolver that can
  report live-ACTIVE / recovery-pending-victim / unknown-GUARD / consumable.

## Proposed v2 wire (unchanged by the ruling, still 416 B body, no mkfs change)

Insert before crc32c — the crc already covers `offsetof(crc32c)` bytes, so it
picks the new fields up automatically, identity triple still appended:
76 fence_kind u16 | 78 fence_resv_type u16 | 80 fence_victim_key u64 |
88 fence_prover_epoch u64 | 96 fence_pr_gen u32 | 100 fence_prover_node u32 |
104 fence_stamp_ms u64 | 112 reserved u32 | 116 crc32c u32  → desc 120 B,
`mxfs_recov_body.pad` 336 → 296.

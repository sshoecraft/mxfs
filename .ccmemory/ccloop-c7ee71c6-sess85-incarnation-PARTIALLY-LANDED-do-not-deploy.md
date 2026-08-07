---
name: ccloop-c7ee71c6-sess85-incarnation-PARTIALLY-LANDED-do-not-deploy
description: sess85: incarnation landing is HALF-WRITTEN in the tree (uncommitted, unbuilt) + the GPT ruling on the rejoin hazard + the pass-1 proof that makes it…
metadata:
  type: reference
tags: [sess85, disklock, incarnation, epoch, rule5, gpt-ruling, in-flight, do-not-deploy]
---

# sess85 — incarnation landing PARTIALLY WRITTEN. Tree is mid-landing.

VERSION still 0.11.419, **not bumped, not built, not deployed**. `dlm/disklock.c`
has uncommitted edits. DO NOT DEPLOY until the "remaining" list below is done —
the ruling requires publication+validation to activate ATOMICALLY with the
proto_gen bump.

## The proof that unblocked the whole design (verify-once, do not re-derive)

GPT made the same-slot supersession conditional on "claim-time takeover
preserves all slot recovery state". **It does.** Verified by line:

- The journal slice is **SLOT-indexed, never incarnation-indexed**: own slice is
  `mp->m_mxfs_node_slot % m_mxfs_log_node_count` (xfs/xfs_mount.c:1039-1044),
  foreign replay is `dead_slot % m_mxfs_log_node_count` (xfs/xfs_log.c:768-772).
  Same mapping. So slot S's obligations survive any change of occupant.
- Claim writes ONLY the 512B heartbeat record in the disklock region. It never
  touches the log slice — no head/tail reset, no generation bump, no zeroing.
- **Pass-1 own-stamp reclaim matches on `node_id` ONLY** — disklock.c CAW pass-1
  and `claim_slot_noncaw` pass-1 both test
  `magic && flags==ACTIVE && node_id==local_node && !gen_foreign`. **No epoch
  test, and there must never be one.** A rebooted node therefore still reclaims
  its own slot, gets `slice_adopted=false`, and FULLY replays its previous
  incarnation's records. Adding an epoch equality test there would push every
  rebooted node onto a pass-2 fresh claim, whose `XLOG_MXFS_ADOPTED_SLICE` gate
  suppresses image replay — **silently abandoning that node's own journal
  slice**. This is the single most dangerous edit not to make; a comment at the
  claim_slot draw site now says so.

## Landed in the tree already

1. `hb_draw_incarnation()` + `inc_valid()` + `inc_eq()` — inserted after
   `hb_gen_foreign()`. Bounded 16-draw loop; returns 0 only on the PAL's one
   real failure mode (user backend zero-fills when /dev/urandom won't open).
2. `mxfs_disklock_create()` — draws, fails closed (frees ctx, returns NULL).
3. `mxfs_disklock_claim_slot()` — REDRAWS per tenancy, fails closed with -EIO.
   Covers the non-CAW path (claim_slot_noncaw is only reachable from here).
4. `recov_desc_names()` / `recov_lease_covers()` **split** into `_node` /
   `_inc` — the optional-epoch form is GONE from the file (grep confirms). All
   4 legacy `(…, 0)` callers routed to `_node` (they are purge/occupancy tests
   whose authority comes from elsewhere).
5. `hb_still_dead_stamp()` — required match, with a documented node-scoped
   degrade when `pe == 0`. The **rejoin release** (`epoch B != pending A` ⇒ not
   still dead) now works for the first time.
6. 13 substitution groups converting every `owner_epoch == ctx->epoch`,
   `fence_prover_epoch == ctx->epoch` and `victim_epoch && …` predicate to
   `inc_eq()`. Snapshot re-read comparisons (`d1->… != snap.…`) deliberately
   left as plain `!=` — they detect ANY change, which is correct.
7. `mxfs_disklock_slot_holds_incarnation()` — zero guard added (it returned
   FALSE = "departed" for a zero epoch against a real record, inverting its own
   fail-closed contract).

## REMAINING (in order)

1. **`recovery_begin` supersession.** disklock.c ~:2596 still only WARNS
   (`P234-RECOV-EPOCH-DRIFT`) and adopts the SECTOR's epoch. Replace with the
   typed outcome. GPT: use a NAMED result, not an overloaded errno — return
   `-EREMCHG` at the API boundary but name it `MXFS_RECOVERY_SUPERSEDED`.
   Emit it ONLY when the sector is: valid crc/format, current proto_gen, same
   slot, ACTIVE, same node_id, expected epoch nonzero, sector epoch nonzero,
   and A != B. Anything malformed/zero/wrong-gen/guard/conflicting-node is NOT
   supersession — fail closed.
2. **The pending-marker bug I found (worse than the memo said).**
   `mark_recovery_pending()` copies `ctx->node_track[slot].last_epoch`
   (disklock.c ~:2219 pre-edit), but the epoch-change path at ~:952 does
   `nt->last_epoch = rhb->epoch;` (adopting **B**) *before* `goto fire_dead`.
   So `pending_epoch[slot]` would name the **LIVE** incarnation as the victim —
   and under the new required-match that MATCHES, so recovery would lay a guard
   on a live node. Fix: carry the victim epoch (A) explicitly through
   fire_dead → expire_cb → mark_recovery_pending; do not let it read
   `last_epoch` back.
3. **Compare-and-clear the pending marker**, keyed on
   `(proto_gen, slot, victim_node, victim_incarnation)`. An A-completion must
   not clear a newly installed pending recovery for B.
4. **Monitor rebase.** After supersession: rebase `nt->last_epoch` and
   `last_timestamp` to B, keep monitoring B, and **immediately dead-check B** —
   an ACTIVE record proves ownership, NOT liveness. Without this an
   already-dead B leaves A cleared and B never scheduled.
5. `v5_mount.c:2105-2124` — treat the superseded code like the existing
   `-ENOENT` arm: clear pending, distinct probe, return 0. Not `FENCEFAIL`
   (that path deliberately retries ⇒ livelock against a live node).
6. **`MXFS_PROTO_GEN` 2 → 3** at `include/mxfs/mxfs_super.h:71` — LAST, atomic
   with the above.
7. Build (`make clean` first — edits span .c/.h), bump VERSION, rig-verify.

## NEW DEFECT for the ledger (do not fix inside this landing)

**Per-node PR fence evicts a live rejoined incarnation.** Recovery identity is
`(slot, incarnation)`; the fence domain is the SCSI-PR registrant / I_T nexus,
i.e. the whole NODE. If node N crashes on slot S, a survivor lays a guard and
then N reboots and mounts on slot T (possible because pass-1 skips a
RECOVERY_GUARD slot), the survivor's per-node PR fence of victim A **also
evicts the live incarnation B on slot T**. Exists today, independent of this
change. GPT's stated invariant: *"Liveness of one incarnation must never
suppress recovery of another incarnation merely because they share a node
identity or fencing domain"* — and conversely a fence of the broader domain
must account for every live incarnation in it. Related to
D-PR-FENCE-PREEMPT-WITHOUT-ABORT / D-FENCED-STAGE-WITHOUT-PROVEN-EXCLUSION.

## GPT's audit list for newly-live predicates

epoch-as-boolean/wildcard; node-only identity predicates (classify each as
logical-recovery vs physical-fence identity); slot-indexed cached state that
survives an epoch change (fence-issued bits, journal-clean flags, "already
warned" bits); queued/delayed work carrying a stale tuple (an A callback must
not mutate B); guard release requiring the matching recovery transaction;
journal generation/replay filtering; crash ordering around `settle_own_slot()`;
duplicate node_id admission; mixed-proto-gen records.

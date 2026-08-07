---
name: ccloop-c7ee71c6-sess86-incarnation-landing-part2-DO-NOT-DEPLOY
description: sess86: incarnation landing parts 1-4 of 7 written (uncommitted, UNBUILT). Exact remaining edit list + the two extra defects found and fixed en route.
metadata:
  type: reference
tags: [sess86, disklock, incarnation, epoch, in-flight, do-not-deploy, supersession]
---

# sess86 — incarnation landing, part 2. STILL MID-LANDING.

VERSION still **0.11.419**, `MXFS_PROTO_GEN` still **2**, nothing built, nothing
deployed. `dlm/disklock.c` + `dlm/disklock.h` have uncommitted edits.
DO NOT DEPLOY: publication+validation must activate atomically with the
proto_gen bump (sess85 ruling).

Supersedes the "REMAINING" list in
`ccloop-c7ee71c6-sess85-incarnation-PARTIALLY-LANDED-do-not-deploy`; everything
that memo says is *landed* is still landed. Read it first for the pass-1
own-stamp proof (**never add an epoch test to claim pass-1**) — that is the
load-bearing fact behind all of this.

## Done this session (sess85 remaining items 1-4)

**disklock.h**
- `mxfs_disklock_expire_cb` → `(void *data, mxfs_node_id_t dead_node, int
  dead_slot, mxfs_epoch_t dead_epoch)`. The victim incarnation is now an
  argument, never a read-back.
- `mark_recovery_pending(ctx, slot, node, victim_epoch)`.
- `clear_recovery_pending(ctx, slot, node, victim_epoch)` → now **int**,
  compare-and-clear: 0 cleared / -ESTALE marker names another victim (left
  intact) / -ENOENT nothing pending. There is deliberately **no unconditional
  clear** — that was the bug.
- New `mxfs_disklock_node_epoch(ctx, slot)` for callers holding only a node id
  (the lease layer).
- `confirm_dead_mask(..., uint64_t *out_confirmed, mxfs_epoch_t *out_epoch)` —
  declared, **implementation not yet updated** (see remaining #1).
- `#define MXFS_RECOVERY_SUPERSEDED (-EREMCHG)` with the full emission
  precondition list in the comment.

**disklock.c**
- Monitor per-slot body: `victim_node` snapshotted BEFORE the auto-monitor
  re-arm can retarget `slot_node_id[]`; `victim_epoch` set explicitly on every
  path into `fire_dead`; `expire_cb` now passes `(victim_node, slot,
  victim_epoch)`.
- Epoch-change arm no longer adopts the successor before firing. New
  `rebase_only:` label + rebase block after `fire_dead`: successor inherits
  `live = true` (an ACTIVE record proves **ownership, not liveness** — GPT
  sess85), so a dead-on-arrival successor still reaches `check_dead`.
- New `P237-SLOT-REOCCUPIED`: if the pending marker already names exactly
  `{victim_node, victim_epoch}`, the successor tenancy does **not** re-declare
  the death (whose first act is a per-NODE fence against a now-live node) — it
  only rebases.
- `P163-RECOVERED` branch now retires the victim's tracking state with the
  victim: rebase onto a successor if the slot is ACTIVE/current-gen, else
  forget the slot (`last_epoch = 0`). Without this the next occupant reads as
  an epoch change against an already-fully-recovered node = spurious second
  death + per-node fence.
- `recovery_begin`: `P234-RECOV-EPOCH-DRIFT` (warn + adopt the sector's epoch)
  **replaced**. Now `P237-RECOV-SUPERSEDED` (all preconditions hold) /
  `P237-RECOV-INC-MISMATCH` → -ESTALE (fails closed) /
  `P237-RECOV-INC-UNOBSERVED` (victim_epoch == 0, adopt as before).
  `hb_feature_state` is defined at :263, well before :2739 — no forward decl
  needed.

## Two extra defects found and fixed en route (log in the ledger)

1. **Auto-monitor clobbers the victim's identity.** The `P-EVICT-AUTOMON`
   re-arm sets `slot_node_id[slot] = rhb->node_id` whenever `!monitored[slot]`
   — which recurs after every `fire_dead`. The epoch-change arm that follows
   in the SAME pass then fired the death using the successor's node id. Fixed
   by the pre-scan `victim_node` snapshot.
2. **Completed recovery left `node_track[].last_epoch` pinned to the departed
   incarnation** → spurious second death for the next occupant. Fixed in the
   `P163-RECOVERED` branch.

## REMAINING (in order) — this is the whole rest of the landing

1. **`confirm_dead_mask` impl** (disklock.c ~:5265): add the `out_epoch`
   parameter and copy `base_epoch[slot]` into it for every confirmed slot. It
   already keeps `base_epoch[]` internally and drops any slot whose epoch
   changed, so the baseline epoch IS the confirmed victim incarnation.
2. **`dlm/mount.c`** — TCP path. `disklock_expire_cb` (registered at :2203,
   distinct from `lease_expire_cb` at :1085) needs the new 4-arg signature.
3. **`dlm/v5_mount.c`** — the bulk:
   - Split `v5_lease_expire_cb`: keep the 2-arg form for
     `mxfs_lease_set_expire_cb` (:2590, :2929) resolving the epoch via
     `mxfs_disklock_node_epoch`; add a 4-arg `v5_disklock_expire_cb` for
     `mxfs_disklock_set_expire_cb` (:2532, :2822). Shared body takes
     `(node, slot, epoch)`.
   - `v5_start_slice_recovery` / `v5_defer_slice_recovery`: take and forward
     `victim_epoch`.
   - Settle sweep :1692 + the `confirm_dead_mask` call :1605: add a
     `mount_stale_epoch[MXFS_DISKLOCK_HB_SLOTS]` array to `struct mxfs_v5_dlm`,
     pass it as `out_epoch`, feed it to `mark_recovery_pending`.
   - `mxfs_v5_dlm_recovery_complete` (:2056): capture `pending_epoch` ONCE into
     a local at entry (do not re-read it after `recovery_begin` may have
     changed state); handle `MXFS_RECOVERY_SUPERSEDED` like the existing
     `-ENOENT` arm — clear pending, distinct probe (`P237-COMPLETE-SUPERSEDED`),
     **return 0**. NOT `FENCEFAIL` (that path retries ⇒ livelock against a live
     node). Both `clear_recovery_pending` sites (:2114, :2218) become
     compare-and-clear with `(dead_node, pending_epoch_local)`.
4. **`MXFS_PROTO_GEN` 2 → 3** at `include/mxfs/mxfs_super.h:71` — LAST, atomic
   with everything above.
5. `make clean && make modules` (edits span .c/.h), bump VERSION, then
   `MXFS_FORCE_PREP=1 ./run.sh 32 caw prep_cluster` and rig-verify.

## Rig verification to design for (not yet run)

The point of the whole change: kill a node at 32/caw and confirm the survivor's
pending marker names a **nonzero, node-specific** incarnation
(`P163-RECOVERY-PENDING ... epoch=<nonzero>`), that a rebooting victim produces
`P237-RECOV-SUPERSEDED` rather than a guard on the live successor, and that
`P237-SLOT-REOCCUPIED` appears instead of a second fence. Also confirm no
`P237-PENDING-REARMED` under normal operation.

## Still-open adjacent defect (ledgered, not fixed here)

Per-node PR fence evicts a live rejoined incarnation — recovery identity is
`(slot, incarnation)` but the SCSI-PR fence domain is the whole node. The
`P237-SLOT-REOCCUPIED` suppression narrows the window but does not close it:
the FIRST observation of an epoch change still declares the death, and its
first act is a per-node fence. Adjacent to
D-PR-FENCE-PREEMPT-WITHOUT-ABORT / D-FENCED-STAGE-WITHOUT-PROVEN-EXCLUSION.

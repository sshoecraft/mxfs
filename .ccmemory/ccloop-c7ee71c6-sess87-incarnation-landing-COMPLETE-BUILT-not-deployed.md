---
name: ccloop-c7ee71c6-sess87-incarnation-landing-COMPLETE-BUILT-not-deployed
description: sess87: incarnation landing is CODE-COMPLETE and BUILDS CLEAN (0.11.420, proto_gen 3). Not deployed, not rig-verified. Next step is exactly the rig c…
metadata:
  type: reference
tags: [sess87, disklock, incarnation, epoch, proto-gen, built, not-deployed, rig-verify-next]
---

# sess87 — incarnation landing CODE-COMPLETE and BUILT

Supersedes the REMAINING list in
`ccloop-c7ee71c6-sess86-incarnation-landing-part2-DO-NOT-DEPLOY`. All 5 of its
remaining items are DONE.

**Build**: VERSION **0.11.420**, `MXFS_PROTO_GEN` **3**, `make clean && make
modules` clean — zero errors, zero new warnings in `dlm/`. The .ko built before
the VERSION bump was srcversion `33018595D555FBE463F017B` (prior tree was
`4A60BCF3FAAA80055570F20`). The VERSION bump landed AFTER that build, so
**rebuild and re-read `modinfo mxfs.ko`** rather than trusting either string.

**NOT deployed. NOT rig-verified. Nothing measured. Uncommitted.**

## What landed this session (sess86 items 1-5)

1. `confirm_dead_mask` gained `mxfs_epoch_t *out_epoch` — zeroed for all slots
   up front, filled with `base_epoch[slot]` for confirmed slots only. That
   baseline is the incarnation held frozen across the whole window, so it is
   the proven-dead one; a later sector re-read would race the victim's reboot.
2. `dlm/mount.c` (TCP path) `disklock_expire_cb` -> 4-arg. Its body is entirely
   node-scoped and marks nothing pending, so slot/epoch are logged (added to
   the existing failover warn) and otherwise unused.
3. `dlm/v5_mount.c` bulk:
   - `struct mxfs_v5_dlm` gained `mount_stale_epoch[MXFS_DISKLOCK_HB_SLOTS]`.
   - `v5_start_slice_recovery` / `v5_defer_slice_recovery` take + forward
     `victim_epoch`.
   - Callback SPLIT: shared `v5_handle_node_death(ctx, node, slot, epoch)`;
     `v5_lease_expire_cb` (2-arg, passes `(-1, 0)`) stays on
     `mxfs_lease_set_expire_cb`; new `v5_disklock_expire_cb` (4-arg) on
     `mxfs_disklock_set_expire_cb` (both registration sites converted).
     `dead_slot < 0` means "resolve here", preserving the historical
     resolve-after-fence ordering.
   - Settle: `confirm_dead_mask` now fills `ctx->mount_stale_epoch`, which
     feeds both mark-pending sites (dispatch and mount-barrier).
   - `recovery_complete`: `dead_epoch` captured ONCE at entry alongside
     `dead_node`; all three `clear_recovery_pending` calls are compare-and-clear
     with that snapshot; new `MXFS_RECOVERY_SUPERSEDED` arm returns **0** after
     clearing (NOT the FENCEFAIL retry path — that would livelock re-deriving
     the same supersession against a now-live node). New probes
     `P237-COMPLETE-SUPERSEDED` and `P237-COMPLETE-REARMED`.
4. `MXFS_PROTO_GEN` 2 -> 3 with the mixed-version rationale written into
   `include/mxfs/mxfs_super.h`.

## DELIBERATE DIVERGENCE from the sess86 plan — do not "fix" this back

sess86 item 3 said the lease path should resolve the victim epoch via
`mxfs_disklock_node_epoch`. **That is wrong and was not done.** It contradicted
the header contract written in the same session (which says the lease layer
passes slot -1, epoch 0).

`node_epoch()` returned `node_track[slot].last_epoch` = "who is in this slot
NOW", not "who died" — the exact category error the whole change removes from
`mark_recovery_pending`. Feeding it to the lease path names a live successor as
victim AND marks it `inc_valid`, so `recovery_begin`'s incarnation test MATCHES
and publishes a guard against a healthy member *with every appearance of having
been verified*. Passing 0 takes `P237-RECOV-INC-UNOBSERVED` instead: same
outcome as before this campaign, labelled unproven rather than fabricated.

0 is also the TRUE answer wherever the value is consumed: `v5_start_slice_recovery`
returns early when the slot is already pending, so `dead_epoch` only reaches the
marker when the monitor has NOT declared the death — i.e. when the lease really
is the sole witness and really never observed an incarnation stop.

`mxfs_disklock_node_epoch` was therefore **DELETED** (decl + impl), replaced by
a header comment explaining why no such accessor may exist. Do not reintroduce it.

## Also fixed en route

`v5_dispatch_late_deaths` named the victim from the mphase snapshot, which goes
stale if the slot was re-armed for a successor. Now reads
`mxfs_disklock_pending_node()` and logs both (`node=%u (recorded as %u)`).
Dispatch was already slot-scoped and correct; the log line was not.

## NEXT STEP — this is the whole remaining task

1. `make modules` (VERSION bumped after the last build), record `modinfo
   mxfs.ko | grep srcversion`.
2. `MXFS_FORCE_PREP=1 ./run.sh 32 caw prep_cluster` (72-137s). **The proto_gen
   bump REQUIRES the re-mkfs** — `tools/mkfs_mxfs.c:569` stamps
   `cluster_proto_gen = MXFS_PROTO_GEN`, and a gen-2 volume will refuse to
   mount gen-3 code. prep_cluster does re-mkfs, so this is covered; do NOT try
   to deploy onto the existing gen-2 LUN.
3. Rig verification designed in the sess86 memo:
   - kill a node at 32/caw -> survivor logs `P163-RECOVERY-PENDING slot=N
     node=M epoch=<NONZERO>` (the whole point; sess83 measured epoch=0 on all
     31 live records).
   - rebooting victim -> `P237-RECOV-SUPERSEDED` + `P237-COMPLETE-SUPERSEDED`,
     NOT a guard on the live successor.
   - `P237-SLOT-REOCCUPIED` instead of a second fence.
   - `P237-PENDING-REARMED` / `P237-COMPLETE-REARMED` must NOT appear under
     normal operation.
   - confirm no `P237-RECOV-INC-MISMATCH` (fail-closed -ESTALE) in the steady state.
4. Then full board, then unblock D-FOREIGN-REPLAY-UNGATED-IMAGES step 5.2,
   which was blocked on this defect.

## Still-open adjacent defect (ledgered, unchanged)

Per-node PR fence still evicts a live rejoined incarnation: recovery identity
is `(slot, incarnation)` but the SCSI-PR fence domain is the whole node.
`P237-SLOT-REOCCUPIED` narrows the window; the FIRST observation of an epoch
change still declares the death and its first act is a per-node fence. Adjacent
to D-PR-FENCE-PREEMPT-WITHOUT-ABORT / D-FENCED-STAGE-WITHOUT-PROVEN-EXCLUSION.

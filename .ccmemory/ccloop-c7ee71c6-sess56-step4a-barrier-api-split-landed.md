---
name: ccloop-c7ee71c6-sess56-step4a-barrier-api-split-landed
description: sess56: 0.11.400 lands the DLM-side API split for GPT's option-D pre-mountfs recovery barrier. Behaviour still identical to 0.11.399 — call site pend…
metadata:
  type: reference
tags: [foreign-replay, mount, recovery, deadlock, step4a, in-progress]
---

# sess56 — step 4a mount-ordering fix, part 1 of 2 (0.11.400)

Implements the DLM half of GPT's option D from
`ccloop-c7ee71c6-sess55-step4a-mount-ordering-inversion-GPT-ruling`.
**Builds clean; srcversion `E734C49BAF50F1E80D9BFC9`. Behaviour is still
byte-for-byte 0.11.399 — the barrier CALL SITE has not landed yet, so this
build carries the same bootstrap deadlock. DO NOT BOARD IT.**

## What landed (`dlm/v5_mount.c`, `dlm/v5_mount.h`)

`mxfs_v5_dlm_mount_settle` was one post-`xfs_mountfs` unit. Split into:

- `v5_settle_resolve(ctx, dispatch)` — new static core shared by the settle
  worker and the coming barrier. Confirm-dead (one baseline, identity per
  sample) → fence → note dead → mark recovery pending. Purges nothing.
  - `dispatch=true` (worker): `v5_start_slice_recovery` — elect + notify,
    async replay. `v5_settle_worker_fn` is now a one-line wrapper.
  - `dispatch=false` (barrier): `mxfs_disklock_mark_recovery_pending` only,
    no election — the mounting node must resolve these itself because its
    own recovery is what collides with the grants. Returns the mask.
  - NEW: sets `ctx->mount_stale_mask = residue` (fence-failures only), so
    phase 3 has something well-defined to retry.
- `mxfs_v5_dlm_settle_own_slot(ctx)` — old phases 1+2 (own-slot
  SKIP_TRACKED purge, then close the adopt window; that order is
  load-bearing).
- `mxfs_v5_dlm_mount_recovery_cohort(ctx, &slots)` — barrier entry point.
- `mxfs_v5_dlm_mount_cohort_complete(ctx, slots)` — the deferred
  `mxfs_v5_dlm_recovery_complete` purges, run only after the WHOLE cohort
  is durably replayed (GPT's cross-slice evidence rule).
- `mxfs_v5_dlm_mount_settle(ctx)` — now phase 3 ONLY (async retry of the
  residue).

`xfs/xfs_mxfs_dlm.c::mxfs_dlm_mount_recovery_settle` temporarily calls
`settle_own_slot()` then `mount_settle()` back to back, which reproduces
0.11.399 exactly. That pair is what the next step MOVES.

## What is left (part 2)

1. Split the perag walk out of `mxfs_dlm_peer_joined_flush`
   (`xfs/xfs_mxfs_dlm.c:41042`) into `mxfs_dlm_invalidate_cached_views(mp)`.
   The barrier needs the invalidation but MUST NOT call
   `xfs_log_force`/`xfs_ail_push_all_sync` — at barrier time the AIL holds
   recovered INTENT items `xlog_recover_finish` has not processed.
   Upstream says the same thing at `xfs/xfs_log.c:868`.
2. New `mxfs_dlm_mount_recovery_barrier(mp)` in `xfs/xfs_mxfs_dlm.c`:
   - `mxfs_blkdev_flush_epoch(mp)` (our own replayed images durable;
     `xlog_recover` pass2 already `xfs_buf_delwri_submit`s them, so no log
     force is needed)
   - `mxfs_v5_dlm_mount_recovery_cohort()` → per slot: flush+invalidate,
     `mxfs_xlog_recover_foreign_slice(mp, slot)`, flush+invalidate
     (mirrors `mxfs_dlm_foreign_replay_work_fn`, minus the AIL push)
   - `mxfs_v5_dlm_mount_cohort_complete()`
   - `set_bit(slot, mp->m_mxfs_sweep_pending_slots)` — do NOT call
     `mxfs_survivor_sweep_slot` here (needs iget/transactions); the reap
     worker at `xfs_mxfs_dlm.c:31257` consumes the bitmap post-mount
   - `mxfs_v5_dlm_settle_own_slot()`
3. Call it from `xfs/xfs_mount.c` right after the `xfs_log_mount` error
   check (line 1057), before `xfs_inodegc_start` at 1077. **`xfs_mount.c`
   does not include `xfs_mxfs_dlm.h` — add the include.**
4. Trim `mxfs_dlm_mount_recovery_settle` to: schedule the deferred sweeps
   (`mxfs_reap_sched`) + `mxfs_v5_dlm_mount_settle` residue retry. Drop its
   double log-force/AIL-push/flush round (that work moved to the barrier).
5. Record the crash-mount 62 s confirm cost in
   `tests/criteria/TIMEOUT_BUDGETS.md` (RULE 0).

## Verified facts backing the design

- `xfs_initialize_perag` is at `xfs_mount.c:997`, BEFORE `xfs_log_mount`
  (1051) — so the perag invalidation walk is legal at the barrier.
- `mxfs_xlog_recover_foreign_slice` (`xfs/xfs_log.c:742`) needs only
  `m_log`, `m_logdev_targp`, `m_mxfs_log_node_count`,
  `m_mxfs_log_slice_bblks` and its own private shadow AIL. No root inode,
  no live AIL, no transactions.
- `xfs_log_mount_finish` (`xfs/xfs_log.c:823`) is the first cluster-lock
  taker (intent replay + iunlink), and it is at `xfs_mount.c:1175` — well
  after the insertion point.
- The recovery-side authority gate is still REPORT-ONLY (step 3b,
  `xfs_log_recover.c:2081`); enforcement is the untagged-image SKIP
  (P223-FR-UNTAGGED-SKIP). Own-slot bits are not consulted by the foreign
  gate, but the barrier still does the own-slot reclaim LAST for safety.
- `mxfs_defer_reap_init(mp)` runs in `fill_super` BEFORE `xfs_mountfs`
  (`pal/linux/xfs_super.c:3068`), so `m_mxfs_sweep_pending_slots` is
  already initialised at barrier time.

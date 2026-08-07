---
name: ccloop-c7ee71c6-sess57-barrier-landed-GPT-STOPSHIP-8-items
description: sess57: 0.11.401 lands the pre-mountfs recovery barrier (step 4a part 2) — but GPT ruled STOP-SHIP with 8 required changes. DO NOT BOARD. Item 6A is…
metadata:
  type: reference
tags: [foreign-replay, mount, recovery, deadlock, step4a, gpt-ruling, stop-ship, in-progress]
---

# sess57 — mount recovery barrier LANDED (0.11.401), GPT ruled STOP-SHIP

Build: **0.11.401**, srcversion `EF59ED0039F7ED8EF3B03D0`, compiles clean.
**DO NOT BOARD IT.** GPT's RULE-5 review of the implementation found a defect
that RECREATES the very deadlock this change fixes (item 6A below), plus four
more stop-ship correctness items. No rig cycle was spent.

## What landed (part 2 of GPT's option D)

1. `xfs/xfs_mxfs_dlm.c` — split the perag walk out of
   `mxfs_dlm_peer_joined_flush` into new public
   `mxfs_dlm_invalidate_cached_views(mp)`.  No log force, no AIL push, no
   inodegc flush — only cached-state drops, so it is legal before
   `xfs_log_mount_finish`.  `peer_joined_flush` is now the double
   force/push/flush round + a call to it.
2. New `mxfs_dlm_mount_recovery_barrier(mp)`, steps (a)-(e):
   (a) `mxfs_blkdev_flush_epoch`
   (b) `mxfs_v5_dlm_mount_recovery_cohort(&cohort)` — confirm/fence/mark-pending
   (c) per slot: invalidate+flush, `mxfs_xlog_recover_foreign_slice`,
       flush+invalidate, `set_bit(slot, m_mxfs_sweep_pending_slots)`
   (d) `mxfs_v5_dlm_mount_cohort_complete(replayed)` — **replayed mask, not
       cohort** (my own fix, matches GPT item 6C's direction but not its full
       requirement)
   (e) `mxfs_v5_dlm_settle_own_slot`
3. Call site: `xfs/xfs_mount.c`, immediately after the `xfs_log_mount()` error
   check (now ~line 1070), before `xfs_inodegc_start`.  Added
   `#include "xfs_mxfs_dlm.h"` to xfs_mount.c.
4. `mxfs_dlm_mount_recovery_settle` trimmed to: schedule the reap worker when
   `m_mxfs_sweep_pending_slots` is non-empty + `mxfs_v5_dlm_mount_settle`
   residue retry.
5. `tests/criteria/TIMEOUT_BUDGETS.md` — recorded the 62 s
   (`31 × 2000 ms` = `MXFS_DISKLOCK_DEAD_THRESHOLD` × `HB_INTERVAL_MS`)
   conditional mount cost and who pays it.

## GPT verdict: 8 required changes BEFORE any rig run

**6A — STOP SHIP, real deadlock (highest priority).**  Fence-failure residue
is left in `ctx->mount_stale_mask` and its retry is deferred to
`mxfs_dlm_mount_recovery_settle`, which runs AFTER `xfs_mountfs` returns.  But
`xfs_log_mount_finish` runs INSIDE `xfs_mountfs` and can block on an AG lock
held by exactly one of those unfenced stale slots → mount never returns → the
residue retry never runs.  That is the original bootstrap deadlock, restored.
Fix must be one of: abort the mount; retry fencing from a thread already
running independently of mount completion; or make mount-time lock acquisition
detect and drive recovery of a stale owner.

**6B** — a peer healthy at step 6.5 can freeze DURING the 62 s confirm window.
Its grants are not in `mount_stale_mask` and can still block
`xfs_log_mount_finish`.  Need a mount-phase policy for deaths after the
snapshot, not just for peers already frozen on arrival.

**3 — publication is too early.**  Step (d) zeroes the dead HB slot (= "state
consumable") while recovered INTENTS are unprocessed, iunlink has not run, and
the foreign AGI sweep is only queued.  A peer can acquire and mutate a resource
between the broadcast and our own `xfs_log_mount_finish` intent completion.
GPT wants a multi-stage durable state — `FENCED / IMAGES_REPLAYED /
INTENTS_PENDING(quarantined) / CONSUMABLE` — with the HB slot only reaching the
last stage after intent + iunlink recovery, or lock-layer quarantine from the
intermediate stage.  Also: if `xfs_log_mount_finish` FAILS after (d), we have
already purged the manifest and told peers recovery is done, and no later mount
knows the slice still needs finishing.

**Foreign shadow AIL lifecycle is undocumented and must be pinned down**: who
runs the `xlog_recover_finish` equivalent for it, who does intent/done matching,
who completes surviving foreign intents, how relogged intents move to the live
log, how it drains, and what happens when two slices carry intents for the same
metadata.  If it is discarded after image replay, foreign recovery is
incomplete.

**4 — purging our own retained bits before `xfs_log_mount_finish` is not proven
safe.**  GPT agrees intent replay does not need the OLD image gate, but the
retained bits may be protecting resources named by unfinished EFI/RUI/CUI/BUI /
iunlink / reflink work.  Purge-then-reacquire is not atomic; a peer can mutate
in the gap.  Needs a proven adopt/handoff or a quarantine.

**2/5 — invalidator must report incompleteness.**  It preserves dirty/pinned/
IN_AIL/delwri buffers (correct) but then clears `pag_dlm_cached` /
`bast_pending` / `release_pending` / `lineage_open` for the whole AG based only
on holder state.  A skipped buffer means the old cached view still exists, so
the AG must NOT be declared uncached.  Return complete / incomplete-busy /
fatal and only clear lineage on complete.  Also applies to `peer_joined_flush`.
Flag checks before taking the buffer lock are racy.

**6C** — cohort completion must key off a per-slot "fully recovered AND durably
published" mask, not "anything replayed".  A slice that needed no buffer writes
still needs completion; a slice that replayed then failed must not be completed.
Suggested masks: `confirmed_fenced / replay_started / replay_completed /
durability_flushed / intents_completed / sweep_completed / safe_to_publish`.

**6D** — the completion sequence (caw purge → lease unregister →
clear_recovery_pending → disklock purge/zero HB → beacon) has irreversible
publication points with no failure checks.  CAW-purge or flush failure must
block publication.

**6H — verify cross-slice LSNs have a genuine GLOBAL ordering.**  "LSN-gated and
idempotent" only holds if LSNs from different private slices are comparable.
Ordinary XFS LSNs are cycle/block within ONE log.  If each slice generates
overlapping ranges, replay can skip a newer image or overwrite a newer one with
an older one.  (Cross-checks memory `compiled-foreign-replay-crash-consistency`,
which already recorded "non-comparable per-node LSNs" — this is likely a REAL
open hole, not hypothetical.)

**1 — flush-only durability**: probably sufficient for pass-2 buffer images IF
`mxfs_blkdev_flush_epoch` really waits for the flush on EVERY device that can
hold recovered output.  Note `mxfs_blkdev_flush_epoch` SKIPS
`blkdev_issue_flush` entirely when `mxfs_fua_disable` is set (the default since
sess94) — it only bumps the epoch counter.  **That must be audited: the barrier
currently relies on a flush that does not happen in the default config.**

**6G** — audit every barrier callee for state that `mxfs_dlm_cache_init`
formally initialises but that kzalloc does not (locks, waitqueues, work structs,
list heads, timers).  Verified already: `pag_dlm_lock` (libxfs/xfs_ag.c:237) and
`pag_bcache` (:258) are initialised in `xfs_initialize_perag`, which is
xfs_mount.c:997, before `xfs_log_mount` at 1051.

## Verified facts (unchanged, still good)

- `xfs_log_mount_finish` (first cluster-lock taker) is at xfs_mount.c:1175.
- Heartbeat starts at `mxfs_v5_dlm_mount` step 6 (dlm/v5_mount.c:2251), which
  is in fill_super BEFORE `xfs_mountfs` — so our own slot keeps advancing
  through the barrier's 62 s window and peers will not fence us.
- `mxfs_defer_reap_init` runs in fill_super before `xfs_mountfs`, so
  `m_mxfs_sweep_pending_slots` and the reap workqueue exist at barrier time.
- `MXFS_DISKLOCK_DEAD_THRESHOLD`=31, `MXFS_DISKLOCK_HB_INTERVAL_MS`=2000.

## Next session starts here

Work 6A first — it is the one that reintroduces the deadlock, and it is small
compared to 3/4 (the publication-staging redesign).  Then audit
`mxfs_blkdev_flush_epoch`'s no-op-under-fua_disable behaviour (item 1), then
6H's cross-slice LSN ordering, which may be an independent open defect.

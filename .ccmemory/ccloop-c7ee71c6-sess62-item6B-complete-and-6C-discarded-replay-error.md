---
name: ccloop-c7ee71c6-sess62-item6B-complete-and-6C-discarded-replay-error
description: sess62: item 6B COMPLETE (0.11.406 rounds+drain+settle dispatch) and item 6C found a SECOND shipped defect — the foreign-replay return value was disc…
metadata:
  type: reference
tags: [foreign-replay, mount, recovery, step4a, item6B, item6C, defect, in-progress]
---

# sess62 — item 6B finished, item 6C exposed a second shipped defect

Build **0.11.407**, srcversion `C72F20487083A2CA52AC43C`, compiles clean.
**STILL DO NOT BOARD** — GPT items 3 and 4 untouched, no rig cycle since 0.11.401.

## Item 6B — COMPLETE (0.11.406)

Everything sess61 listed as remaining is landed:

- `dlm/v5_mount.c`: internal `v5_take_late_deaths(ctx, nodes)` (copies mask
  AND `mphase_dead_node[]` under `mphase_lock`, clears the mask); public
  `mxfs_v5_dlm_mount_take_late_deaths(ctx)` / `_defer_late_deaths(ctx, slots)`
  (OR-back, cannot lose a concurrent arrival; `mphase_dead_node[]` is never
  cleared so identity survives a take/defer round trip).  Declared in
  `dlm/v5_mount.h`.
- `xfs/xfs_mxfs_dlm.c` barrier step (c) is now **bounded ROUNDS**
  (`MXFS_BARRIER_REPLAY_ROUNDS = 4`).  After each round: `attempted |= todo`,
  shutdown check, drain, `todo = drained & ~attempted` (already-attempted slots
  are never re-run — that is how a cap becomes a spin).  The inner slot loop
  was reindented one tab, not rewritten.
- `mount_cohort_complete(replayed)` remains a **SINGLE** call after ALL rounds
  (sess50 cross-slice evidence rule).  `drained & ~replayed` is handed back
  before it; `drained & replayed & ~published` is handed back inside its
  failure branch so a failing mount still leaves an honest census.
- `mxfs_v5_dlm_mount_settle` gained phase 3a: `v5_dispatch_late_deaths` drains
  and calls **`v5_dispatch_slice_recovery`** (NOT `_start_`, whose
  already-pending guard would return without electing) for each slot still
  `recovery_is_pending`.  It runs from `mxfs_dlm_mount_recovery_settle`, which
  `pal/linux/xfs_super.c:3088` calls after `mxfs_dlm_cache_init` at :3080 —
  i.e. after the slice-replay hook exists.  If the hook is somehow still NULL
  it does NOT drain, so the teardown `P233-MPHASE-UNDISPATCHED` census stays true.
- RULE 6 ledger entry **D-MOUNT-WINDOW-PEER-DEATH-IMMEDIATE-PURGE** (critical,
  OPEN) written to `tests/criteria/OPEN_DEFECTS.json` with the line-proof, the
  fix across 0.11.405/406, the residual, and a 4-step verification plan.

## Item 6C — a SECOND real shipped defect, fixed in 0.11.407

`mxfs_xlog_recover_foreign_slice()` returns an error (`xfs/xfs_log.c:797-810`,
it even warns "foreign replay of slot %u failed") and **both callers discarded
it**: the live `mxfs_dlm_foreign_replay_work_fn` and the mount barrier.  A slice
whose replay FAILED was published exactly like one that succeeded — CAW manifest
purged, HB sector zeroed, peers told it was recovered.  That destroys the only
two pieces of evidence that would make anyone redo the replay, so the dead
node's fsync-acked metadata becomes permanently unreachable.

Striking detail: in BOTH call sites the surrounding steps (pre/post
`peer_joined_flush`, `flush_durable`) already check and refuse.  The replay
itself was the one unchecked step in the sequence.

Fix: both sites check and refuse (barrier → `continue` without setting the
`replayed` bit, after re-invalidating; live path → `MXFS_REAPF_FREPLAY` +
`mxfs_reap_sched`).  New `mxfs_has_log_slices(mp)` in `xfs/xfs_mount.h` isolates
the one legitimate no-replay case (unsliced FS: every node shares one log, ours
already recovered it) by testing the CONFIGURATION rather than aliasing the
`-EINVAL` that function returns for it — same predicate `xfs_mountfs`
(`xfs_mount.c:1038`) uses, so they cannot drift.

Ledger entry **D-FOREIGN-REPLAY-FAILURE-PUBLISHED-AS-RECOVERED** (critical,
OPEN) written with a fault-injection verification plan.

Ledger now: 41 entries, **13 OPEN**.

## Facts established this session (do not re-derive)

- The foreign shadow AIL question GPT raised in sess57 is **answered by
  `xfs/xfs_log.c:722-811`**: intent/done items are SKIPPED entirely during
  foreign replay (`XLOG_MXFS_FOREIGN_REPLAY` gates in `xfs_log_recover.c`),
  the shadow AIL is a private kzalloc'd dummy that is `kfree`d immediately,
  and `xlog_recover_finish` is NEVER run for it.  The slice is deliberately
  left dirty so the next node to CLAIM that slot replays it fully including
  intents.  **That is exactly GPT item 3's hole**: the barrier publishes the
  slot as consumable while the dead slice's EFI/RUI/CUI/BUI intents and its
  AGI unlinked inodes are still unprocessed (the AGI sweep is only queued into
  `m_mxfs_sweep_pending_slots`), and if the cluster never re-claims that slot,
  nobody ever finishes them.  Item 3 is REAL and is the next thing to design.
- Item 4 (own retained bits purged in step (e) before `xfs_log_mount_finish`):
  the sess57 deadlock argument does **not** obviously apply to our OWN bits —
  they are recorded under `ctx->node_slot`, and the acquire fast path ADOPTS
  them (`caw_adopt_retained`), so they block peers, not us.  If that reading
  survives a check of the CAW acquire path's self-slot handling, moving step
  (e) back to after `xfs_log_mount_finish` fixes item 4 without reopening 6A.
  **Verify the self-slot handling before acting on this.**

## Next session

1. Item 3 (publication staging: `FENCED / IMAGES_REPLAYED / INTENTS_PENDING
   (quarantined) / CONSUMABLE`, or lock-layer quarantine) — the biggest one.
2. Item 4, starting from the self-slot reading above.
3. Then ONE RULE-5 consult on the whole barrier before any rig cycle.

---
name: ccloop-c7ee71c6-sess60-item2-5-fixed-invalidator-honesty
description: sess60: GPT item 2/5 FIXED (0.11.404) — the cached-view invalidator now reports incompleteness and callers refuse to publish on it. Item 6H resolved…
metadata:
  type: reference
tags: [foreign-replay, mount, recovery, step4a, invalidation, in-progress]
---

# sess60 — GPT item 2/5 fixed; item 6H resolved (not new)

Build **0.11.404**, srcversion `4F20EAFFD91575C5AEAFC80`, compiles clean
(only the pre-existing platform-header / missing-prototype warnings).
**STILL DO NOT BOARD** — GPT items 6B, 3, 4, 6C remain open.

## Item 6H — RESOLVED as already-tracked, not an independent defect

GPT asked whether cross-slice LSNs have a genuine global ordering.  Answer,
line-verified:

- **INODES are safely gated.** `xfs/xfs_inode_item_recover.c:410-429` already
  branches on `xlog_is_mxfs_untrusted_replay(log)` and uses the
  node-independent `di_changecount` instead of `XFS_LSN_CMP`.
- **BUFFERS are NOT.** `pal/linux/xfs_buf_item_recover.c:1062` does an
  unconditional `XFS_LSN_CMP(lsn, current_lsn)` with no MXFS branch — exactly
  the meaningless cross-slice comparison.  Same at
  `xfs/xfs_dquot_item_recover.c:145`.

That IS `D-FOREIGN-REPLAY-UNGATED-IMAGES` (ledger defect #1), both arms
(false-APPLY reverts a survivor's block; false-SKIP drops the dead node's
acked change).  It is contained today by `mxfs_foreign_replay_untagged_apply=0`
+ the ATOMIC-SKIP taint scan, and the *fix* is campaign **step 5** (swap the
untagged skip for an exact `{class, id, epoch}` authority match).  No new
ledger entry — see `compiled-foreign-replay-authority-tokens`.

## Item 2/5 — invalidator honesty (FIXED)

**`mxfs_dlm_invalidate_ag_meta(pag, &ag_preserved)`** now returns a census
instead of void.  Every `continue` in that walk leaves a buffer in
`pag_bcache` with `XBF_DONE` set and this node's older content in it — which
is the correct conservative choice (clearing DONE on un-destaged committed
content is the proven P47/P131 bnobt lost-update) but means **the cached view
survives the walk**.  Counted at all six skip sites:

- unlocked inode-buf with BLI attached → `ino_pres`
- `b_hold==0` AG-meta with the P47 keep-guard → `ag_pres`
- `b_hold==0` inode-buf (gets no treatment at all — the DONE-clear is AG-meta
  only) → `ino_pres`
- trylock-fail AG-meta with the keep-guard → `ag_pres`
- trylock-fail inode-buf → `ino_pres`
- locked inode-buf with BLI → `ino_pres`

Logs `P232-INVAL-INCOMPLETE` per AG.

**`mxfs_dlm_invalidate_cached_views` is now `int`.**  The pag lineage clear
(`pag_dlm_cached` / `bast_pending` / `release_pending` / `lineage_open`) is
gated on `ag_pres == 0` **in addition to** `holders == 0 && !demoting`.
Declaring the AG uncached while retaining an un-destaged committed buffer
hands the AG to a peer with our overwrite still pending — a publish under no
lineage, i.e. defect #2's family.  Leaving the lineage intact is the safe
direction: the peer's BAST drives our Phase-2 drain first.

Returns `-EBUSY` when any BUFFER was retained.  A **skipped inode** is counted
and logged but deliberately does NOT make it busy: the walk leaves its
`i_dlm_*` state alone, so it keeps claiming exactly the authority it had.

## Callers

- **`mxfs_dlm_peer_joined_flush` is now `int`** and loops the force/push/flush
  round up to `MXFS_INVAL_FLUSH_ROUNDS` (5) until the invalidation comes back
  clean — the flush round *is* the remedy for a retained buffer.  Non-
  convergence is `P232-INVAL-STUCK` + `xfs_force_shutdown`: both alternatives
  (stay cached with possibly no on-disk grant / declare uncached with a
  pending overwrite) are silent corruption.  A `void` shim
  `mxfs_dlm_peer_joined_notify_cb` keeps the DLM `set_peer_joined_notify`
  signature.
- **Live foreign replay** now checks BOTH brackets; either failure re-arms via
  `MXFS_REAPF_FREPLAY` and leaves the dead-slot bit set.
- **Mount recovery barrier** cannot retry (it may not force the log or push
  the AIL — recovered intents are in it), so it refuses the slice: pre-replay
  `-EBUSY` skips the replay entirely, post-replay `-EBUSY` keeps the slot out
  of `replayed` so step (d) never publishes it.  Also reordered so the
  durability flush is checked before the second invalidate.

## Files touched

`xfs/xfs_mxfs_dlm.c`, `xfs/xfs_mxfs_dlm.h`.

## Next session order

1. **Item 6B** — a peer healthy at mount step 6.5 can freeze DURING the 62 s
   confirm window; its grants never enter `mount_stale_mask` and can still
   block `xfs_log_mount_finish`.  Needs a mount-phase policy for deaths after
   the snapshot.
2. **Items 3 and 4 — the big ones.**  3: publication is too early (step (d)
   zeroes the HB slot while recovered INTENTS are unprocessed, iunlink has not
   run and the AGI sweep is only queued) → GPT wants durable stages
   FENCED / IMAGES_REPLAYED / INTENTS_PENDING(quarantined) / CONSUMABLE, plus
   a written-down foreign shadow-AIL lifecycle.  4: purging our own retained
   bits before `xfs_log_mount_finish` is unproven — those bits may protect
   resources named by unfinished EFI/RUI/CUI/BUI/iunlink work, and
   purge-then-reacquire is not atomic.
3. **Item 6C** — re-read GPT's per-slot `safe_to_publish` requirement against
   what the sess59 `published` mask + sess59/60 per-slice gates now provide;
   much of it may already be satisfied.
4. **RULE-5 consult on the whole set before any rig cycle.**  Nothing from
   sess57 onward has been measured on the rig yet.

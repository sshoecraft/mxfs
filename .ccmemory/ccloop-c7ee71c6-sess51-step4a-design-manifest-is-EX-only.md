---
name: ccloop-c7ee71c6-sess51-step4a-design-manifest-is-EX-only
description: sess51 step-4a design: the authority manifest is EX/PW-only, so purging stale PR/CR bits at mount kills the sess50 self-conflict blocker entirely.
metadata:
  type: reference
tags: [foreign-replay, D-FOREIGN-REPLAY, step4, purge-ordering, dlm_caw, v5_mount, design]
---

# Step-4a design — the manifest is EX-only (sess51)

Consumes [[ccloop-c7ee71c6-sess50-GPT-ruling-step4-ordering-and-two-new-defects]]
and [[ccloop-c7ee71c6-sess50-step4-code-facts-purge-ordering]].
Campaign: [[compiled-foreign-replay-authority-tokens]]. All line-verified @0.11.398.
**No code shipped in sess51** — design + code recon only.

## The finding that removes sess50's implementation blocker

sess50 concluded the CLAIM-B fix needed GPT's `RECOVERING_OLD_INCARNATION`
self-conflict bypass, because a retained stale bit at a mode *different* from the
one being requested falls into the normal wait, `v5_caw_holders_alive` reports the
holder alive (it is our own reclaimed, heartbeating slot), and the wait is
liveness-extended to the 8-minute hardcap → we wait on ourselves, then fail the
mount. **That blocker is avoidable. The bypass is not needed.**

Three line-verified facts compose:

1. **`caw_grant_epoch_update` stamps `ex_grant_epoch` only for EX/PW**
   (`dlm/dlm_caw.c:946`). PR/CR/CW grants carry **no authority** and are not part
   of the manifest.
2. **The XFS overlay never requests PW or CW.** Occurrence count in
   `xfs/xfs_mxfs_dlm.c`: `MXFS_LOCK_EX`×90, `MXFS_LOCK_NL`×62, `MXFS_LOCK_PR`×27,
   `MXFS_LOCK_CR`×1, `MXFS_LOCK_PW`×0, `MXFS_LOCK_CW`×0.
3. **`node_held_mode` returns the STRONGEST mode held** (`dlm_caw.c:433-436`,
   order EX>PW>PR>CW>CR).

Therefore, if mount purges our own stale **PR/CR/CW** bits but retains **EX/PW**:
`our_mode` is either NL (nothing retained) or EX. EX ≥ every mode the FS can
request, so every acquire lands on the `our_mode == mode` fast path (`:3768`) or
the `our_mode >= mode` subsume path (`:3897`). **Both grant without a CAS, without
a `generation++`, and without calling `caw_grant_epoch_update`** — the epoch is
preserved *and* there is no wait. The `our_mode < mode` hang case cannot arise.

Both fast paths run `compatible_excluding_self`, so a peer co-holding an
incompatible mode still forces the P37 divergence clear — that stays intact.

## Residual hazard of adopting a stale EX bit, and why it is contained

The adopt path skips the fresh-grant AG-meta invalidation / FUA re-read.
Contained because (a) the buffer cache is empty at mount, (b) nobody could have
written the resource — the retained EX bit blocked every peer, and (c) the window
closes at the post-mountfs settle, before `mxfs_init_all_perag_data`. Only
acquires *inside* `xfs_mountfs` (recovery, intent processing, summary counts) see
it, which is exactly the set that must run under the retained authority.

## The other two questions sess50 left open

**Can a BAST steal the retained EX bits?** No.
- Disk-poll BAST scan (`dlm_caw.c:6488`) iterates `ctx->held.slots` — the *local*
  tracking array, empty on a fresh ctx. Un-tracked stale bits are never scanned.
- UDP BAST recv (`:6702`) fires `bast_cb` unconditionally, but
  `mxfs_dlm_ag_bast_notify` (`xfs_mxfs_dlm.c:38556`) only schedules the release
  work when `pag->pag_dlm_cached` is true. A stale on-disk bit has no in-core
  state (`holders==0, cached=false`) → nothing scheduled. (It does set
  `bast_pending` and after 3 s arms `orphan_nak`, a TCP-master concept — verify
  that path is inert under CAW before shipping.)

**Can the mount-time cross-instance stale purge (CLAIM C) just be deleted and
left to the monitor?** No. `check_dead` (`disklock.c:748`) requires `nt->live`,
and `live` only latches after `MXFS_DISKLOCK_LIVE_THRESHOLD` *changed* samples. A
slot already frozen when we first see it never advances `changed_samples`, so
`fire_dead` never fires for it. The in-tree comment at `v5_mount.c:1816-1830` is
accurate: these bits are unreachable by any other cleaner. The purge must be
**rerouted**, not removed.

## Planned edit list for 0.11.399 (step 4a)

1. `dlm/dlm_caw.{c,h}` — `mxfs_dlm_caw_purge_dead_nodes_ex(ctx, mask, bool
   keep_exclusive)`; existing `mxfs_dlm_caw_purge_dead_nodes` becomes a wrapper
   with `keep_exclusive=false`. When keeping: skip `holders_ex`/`holders_pw`,
   never `caw_tombstone_slot` (that would erase `ex_grant_epoch`); still strip
   `holders_pr/cw/cr`, `waiters`, `waiters_ex`, `yield_to`, `open_holders`.
2. `dlm/v5_mount.c` step 4 (`:1765`) — call with `keep_exclusive=true`.
3. `dlm/v5_mount.c` step 6.5 (`:1831`) — **record** `ctx->mount_stale_mask`
   instead of purging.
4. New `mxfs_v5_dlm_mount_settle_*` entry points; driver
   `mxfs_dlm_mount_recovery_settle(mp)` in `xfs/xfs_mxfs_dlm.c`:
   barrier (`mxfs_dlm_peer_joined_flush`-style double log-force + AIL push +
   `mxfs_blkdev_flush_epoch`) → purge our own retained EX/PW → for each bit of
   `mount_stale_mask` re-verify still-frozen, then `mark_recovery_pending` +
   `lowest_live_slot` election + `dead_node_notify_fn(slot)`.
   Node id per slot: `mxfs_disklock_get_slot_node_id` (`disklock.h:537`).
5. `pal/linux/xfs_super.c` — call it **after** `mxfs_dlm_cache_init(mp)` (`:3079`,
   which does `INIT_WORK(m_mxfs_foreign_replay_work)` and registers
   `mxfs_dlm_dead_node_notify`) and **before** `mxfs_init_all_perag_data(mp)`.

Step 4b (durable REPLAYED state in the HB record) and step 5 (gate swap) are
unchanged by this and still required — 4a only stops the manifest being destroyed
before replay.

## Timing note

`mxfs_dlm_caw_set_single_node(true)` at `v5_mount.c:1781` makes acquires
in-memory-only, but the membership-settle gate at the tail of `mxfs_v5_dlm_init`
waits for peers, and `v5_mount.c:1018-1024` clears single_node on first peer
sight. In a populated cluster single_node is already **false** before
`xfs_mountfs`, so `xlog_recover` does hit the on-disk CAW table. Do not rely on
single_node to protect the manifest.

---
name: ccloop-c7ee71c6-sess55-step4a-mount-ordering-inversion-GPT-ruling
description: sess55: step-4a as shipped (0.11.399) has a mount BOOTSTRAP DEADLOCK - GPT ruled HOLD THE RIG RUN and move cohort recovery before xfs_log_mount_finis…
metadata:
  type: reference
tags: [foreign-replay, mount, recovery, deadlock, gpt-ruling, step4a]
---

# sess55 - step 4a (0.11.399) mount ordering inversion

**No code was edited this session.** Analysis + RULE-5 consult only. 0.11.399
builds clean and is UNBOARDED. **Do not board it as-is** - GPT ruled hold.

## The defect (line-verified)

fill_super order today (`pal/linux/xfs_super.c:3074-3088`):
`v5_dlm_mount` (6.5 RECORDS stale mask) -> `xfs_mountfs()` ->
`mxfs_dlm_cache_init` -> `mxfs_dlm_mount_recovery_settle`.

`xfs_mountfs` takes blocking cluster locks with **no mount/recovery-phase
guard**:
- `xfs_free_extent` -> unconditional blocking AG EX (`xfs/libxfs/xfs_alloc.c:4868`)
- `xfs_dialloc`/`xfs_difree` (`xfs_ialloc.c:2210`), iunlink insert
  (`xfs_inode_util.c:743`), `xfs_inode.c:3852,5042`
- these run in `xfs_log_mount_finish` -> `xlog_recover_finish` (intent replay)
  and `xlog_recover_process_iunlinks`.
- `__mxfs_ag_dlm_lock` (`xfs/xfs_mxfs_dlm.c:34101`) has NO phase guard.

CAW wait (`dlm/dlm_caw.c:2519-2555`): base 120 s; extends past it ONLY while
every blocker is provably heartbeating (`v5_caw_holders_alive` ->
`mxfs_disklock_slot_live`), hard cap `MXFS_CAW_WAIT_HARDCAP_MS` = 480 s.

Two reachable failures:

1. **Frozen foreign slot** (never heartbeats) -> not live -> break at 120 s ->
   `-ETIMEDOUT` out of `xfs_free_extent` -> `xlog_recover_finish` fails ->
   `xfs_mountfs` fails -> **mount fails**. The settle that would fence/replay/
   release those grants runs only AFTER `xfs_mountfs` returns -> never reached.
   Circular: our recovery needs the foreign grant released; releasing it needs
   the foreign slice replayed; replaying needs a mounted FS.

2. **Mutual retained-bit block (more likely at 32 nodes).** Step 4 KEEPS each
   node's own previous-incarnation EX/PW bits through its whole `xfs_mountfs`,
   released only at the post-mountfs settle phase 1. In a mount storm every
   node is simultaneously heartbeating (so `holders_alive` = TRUE -> the wait
   extends to the 480 s hard cap) AND holding retained bits. Node A's
   `log_mount_finish` blocking on B's retained bit while B blocks on A's is a
   true distributed deadlock resolving only at the hard cap -> all mounts fail.
   Overlap is plausible: `xfs_inactive` frees extents in AGs other than the
   inode's own AG.

Pre-4a this could not happen: step 6.5 purged foreign frozen bits outright
(its own comment: "a previous mount that held root_dir EX deadlocks the next
mount indefinitely").

## Mitigation that limits blast radius (do not rely on it)

`dlm/v5_mount.c:2130` sets `mxfs_dlm_caw_set_single_node(caw, true)` at mount
step 5; `mxfs_dlm_caw_lock` has a `single_node` fast path
(`dlm/dlm_caw.c:3433`) that grants in-memory with no disk I/O. A node mounting
ALONE after a crash therefore never blocks. The hazard needs a live peer
discovered before/during `xfs_mountfs` - i.e. exactly the 32-node rig storm.

## GPT ruling (RULE 5, gpt-5.6-sol)

Verdict: **hold the rig run**; option D - a pre-`xfs_mountfs` cluster-recovery
barrier. Rejected A (strip foreign PR/CR only: leaves the EX deadlock, and a
10 s probe is not authority to mutate a maybe-live peer's sync state) and C
(re-entrant recovery from inside the CAW wait: lock-order/recursion/txn
hazards plus slice-recovery dependency cycles).

Invariant to enforce:
> No normal XFS recovery operation may wait on a dead holder whose release
> depends on recovery that cannot run until `xfs_mountfs()` completes.

Required properties:
- 6.5 records only (already true).
- Slice-recovery machinery available BEFORE ordinary XFS log recovery.
- Barrier resolves confirmed-dead holders before `xfs_mountfs` can block.
- Replay gates read a **stable snapshot** - do not use mutable CAW state as
  both evidence and cleanup target. Replaying slice A must not clear bits that
  slice B's gate still needs.
- EX/PW cleared only after the whole cohort is durably resolved.
- Non-authority bits cleaned only after fencing, never on the 10 s probe.
- The 62 s confirm belongs on the mount path, but only when a stale cohort
  exists; one coordinator, candidates confirmed in parallel.

GPT on the ordering question: per-node LSNs give no global order, so
correctness must come from force-before-conflicting-lock-transfer. **MXFS has
that** - Architectural Invariant 1 (drain pipeline before
`mxfs_v5_dlm_ag_unlock`). Therefore only the final authority generation can
have unresolved conflicting writes per resource, older records are already
durable or rejected by the gate, and slice replay needs no cross-node LSN
order. The foundation is sound; only the mount ordering is wrong.

GPT also flagged: intent replay and iunlink processing need the same
authority/order treatment as buffer-image replay. Gating only buffer images is
insufficient if intent replay mutates the same metadata under newly acquired
locks. NOT yet analysed - open question for the next session.

## The seam (verified) and the concrete plan

`mxfs_xlog_recover_foreign_slice` (`xfs/xfs_log.c:742`) needs only `mp->m_log`,
the slice geometry, and a private shadow xlog with its own dummy AIL. It needs
NO root inode, NO live AIL, NO transactions. So it can run immediately after
`xfs_log_mount()` returns.

In `xfs/xfs_mount.c`: `xfs_log_mount()` at 1051 (our own buffer-image replay
completes inside it); root iget at 1090; `xfs_log_mount_finish()` at 1175
(intent replay + iunlink = the first cluster-lock taker).

**Insertion point: `xfs/xfs_mount.c` right after the `xfs_log_mount` error
check (line 1057), before `xfs_inodegc_start`.** Nothing has taken a cluster
lock yet - buffer replay does not route through `mxfs_ag_dlm_lock`.

New `mxfs_dlm_mount_recovery_barrier(mp)`:
1. `mxfs_blkdev_flush_epoch(mp)` - make our own replayed images durable. Do
   NOT `xfs_ail_push_all_sync` here: the AIL holds recovered INTENT items that
   `xlog_recover_finish` has not processed yet.
2. Foreign cohort, synchronously: confirm dead -> fence -> replay EVERY
   confirmed slice -> flush -> only THEN run the per-slot
   `mxfs_v5_dlm_recovery_complete` purges (deferring all purges to after the
   whole cohort satisfies GPT's cross-slice evidence rule; the on-disk CAW
   table is itself the durable snapshot as long as it is not mutated
   mid-cohort, and a crash mid-cohort leaves every bit intact for re-detection,
   replay being LSN-gated and idempotent - `xfs/xfs_log.c:734`).
3. Defer `mxfs_survivor_sweep_slot` to post-mount via
   `m_mxfs_sweep_pending_slots` (it needs iget/transactions).
4. Run settle phases 1-2 (own-slot reclaim + close adopt window) HERE, before
   `xfs_log_mount_finish`. This is what kills failure mode 2: the retained
   bits exist only to gate image replay inside `xfs_log_mount`, so releasing
   them before any node takes cluster locks removes the mutual block.

New v5 APIs needed (split out of `mxfs_v5_dlm_mount_settle`,
`dlm/v5_mount.c:1495`):
- `mxfs_v5_dlm_mount_recovery_cohort(ctx, &slots)` - synchronous confirm+fence
  +mark-pending; returns the confirmed mask; no purge, no async dispatch.
- `mxfs_v5_dlm_mount_cohort_complete(ctx, slots)` - the deferred purges.
- `mxfs_v5_dlm_settle_own_slot(ctx)` - phases 1-2 only.
Leave `mount_stale_mask` set to the fence-FAILED residue only, and keep
`v5_settle_worker_fn` as the retry for that residue.

Reusable as-is: `mxfs_disklock_confirm_dead_mask` (`dlm/disklock.c:2670`) -
one baseline held across the window, identity (node + epoch) rechecked per
sample, and its loop is `for (i = 0; i < samples && live; i++)` so it
**early-exits when the candidate set empties**. That is what keeps the 32-node
concurrent mount storm cheap: peers that start heartbeating drop out within an
HB interval; only a genuinely dead slot costs the full 62 s.

## RULE 0 note

A crash mount with a genuinely dead cohort will now cost up to 62 s of
confirm on the mount path. That is correctness-required (GPT: there is no
correct fully asynchronous solution when mount recovery already conflicts with
the candidate) and applies only to crash mounts. Record it in
`tests/criteria/TIMEOUT_BUDGETS.md` when the change lands.

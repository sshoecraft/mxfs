---
name: ccloop-c7ee71c6-sess67-owner-term-wire-change-landed
description: sess67: sess66 GPT ruling item 7 LANDED (0.11.410) — owner_term replaces reserved, recovery_gen constant across takeover, mxfs_recov_auth tuple. STIL…
metadata:
  type: reference
tags: [foreign-replay, recovery, descriptor, disklock, owner-term, do-not-board, in-progress]
---

# sess67 — the owner_term wire change is IN (0.11.410)

Build **0.11.410**, srcversion `B9EDF45FFDC01DA13BA8EE9`
(was `F696294F7C2ECCE699E08C3` at 0.11.409).  Clean build, no new warnings.

**STILL DO NOT BOARD.**  0.11.402..410 has never had a rig cycle.  The
last rig run was 0.11.401.

## What landed — sess66 implementation order item 1, complete

The format is free to change: no rig has ever run a build that WRITES a
descriptor, so nothing on disk carries version 1.

`dlm/disklock.h`
- `struct mxfs_recov_desc.reserved` (offset 72) → **`owner_term`**.
  Layout unchanged, still 80 B, all four _Static_asserts still hold.
- `recovery_gen` is now documented as the **recovery TRANSACTION identity,
  CONSTANT from begin() to the final zero**.  `begin()` sets it to 1 and a
  comment at the assignment explains why a constant is correct (a descriptor
  is created at most once per victim incarnation) and explicitly forbids
  turning it back into a takeover counter — that is the ABA hole.
- New **rule 6** in the big header comment: gen = transaction, term =
  authority; why they must be two fields (A → B → A inside ONE session of A
  leaves `{owner_node, owner_epoch}` byte-identical, so a slow A worker
  passes the old check and resumes writing under an authority it lost).
- New **`struct mxfs_recov_auth`** = `{victim_node, victim_epoch,
  recovery_gen, owner_term, victim_slot, stage}`.  Issued by
  `begin()`/`takeover()`, demanded back by `advance()`/`refresh()`.
- New **`MXFS_RECOV_ABANDON_MS 6000`** (GPT ruling item 4).  `MXFS_RECOV_
  REFRESH_MS` stays 1000 and is now only the refresh cadence.
- Header now states the takeover PRECONDITION in force: a stalled stamp is
  the SECOND gate.  The caller must have already confirmed the owner's
  session dead AND fenced from the LUN.  Also states that takeover SLEEPS
  MXFS_RECOV_ABANDON_MS inside the call, so it may never run on the
  heartbeat monitor thread.

`dlm/disklock.c`
- `recov_auth_issue()` / `recov_auth_holds()` helpers.  A NULL auth degrades
  to the pre-sess67 owner-identity test (never used by the coordinator).
- `begin(..., struct mxfs_recov_auth *out_auth)` — sets `owner_term = 1`,
  fills out_auth on success AND on the "already ours" early return.
- `advance(..., const struct mxfs_recov_auth *auth)` — auth recheck replaces
  the bare owner test; on mismatch logs the new **P234-RECOV-NOTOURS** with
  both tuples and returns -EBUSY.
- `refresh(..., const struct mxfs_recov_auth *auth)` — same check, -ESTALE.
- `takeover(..., struct mxfs_recov_auth *out_auth)` — **recovery_gen is now
  PRESERVED**; `owner_term` and `stage_seq` are what move.  The stall probe
  now sleeps `MXFS_RECOV_ABANDON_MS` and compares `owner_term` and `stage`
  in addition to the previous six fields.  P234-RECOV-TAKEOVER log now
  prints `gen=%llu term=%u->%u`.

`dlm/v5_mount.c` — call sites updated so the tree builds:
`mxfs_v5_dlm_recovery_complete` now holds a `struct mxfs_recov_auth auth`,
gets it from `begin()`, and presents it to BOTH `advance()` calls.  That is
strictly better than 0.11.409 (which could advance a descriptor a successor
had taken over) but it is an INTERMEDIATE state — item 4 of the order below
still has to remove the `begin()` from this function entirely.

## Remaining implementation order (unchanged from sess66, item 1 done)

2. **Coordinator thread** in `dlm/v5_mount.c`.  Design worked out this
   session, not yet written:
   - state on `struct mxfs_v5_dlm`: `recov_lock`, `recov_thread`,
     `volatile int recov_stop`, and
     `struct { bool owned, dispatched; mxfs_node_id_t victim;
               struct mxfs_recov_auth auth; } recov[MXFS_DISKLOCK_HB_SLOTS]`.
   - model it on `v5_tcp_death_worker_fn` / `v5_settle_worker_fn`
     (`mxfs_pal_thread_create`, join in `mxfs_v5_dlm_shutdown` at
     v5_mount.c:3080-3098, both already do exactly this).
   - 1 s pass: (a) `refresh()` every owned nonterminal descriptor —
     -ESTALE/-ENOENT = drop ownership, -EPROTO = freeze and never touch;
     (b) acquisition sweep, gated on `ctx->dead_node_notify_fn != NULL`
     (that IS the replay-capability gate, item 5): for each pending slot we
     don't own, `recovery_read()`; -ENOENT + elected (`lowest_live_slot ==
     local_slot`) → `begin()`; descriptor owned by us → adopt via the
     idempotent `begin()`; descriptor owned by a node that is
     `v5_node_is_dead()` AND `!mxfs_disklock_slot_live(d->owner_slot)` →
     `takeover()`; otherwise leave alone.
   - dispatch is CHEAP and safe from this thread: `dead_node_notify_fn` is
     `mxfs_dlm_dead_node_notify` (xfs_mxfs_dlm.c:42221), which only sets a
     bit in `m_mxfs_foreign_dead_slots` and queues
     `m_mxfs_foreign_replay_work` on `system_unbound_wq`.
   - **OPEN HOLE to close in the same increment:** the acquisition sweep is
     driven by `recovery_pending_iter`, and the pending marker is PER-NODE
     VOLATILE (sess66 proof).  If every witness of a death reboots, no node
     has a marker and an abandoned descriptor is never taken over.  Fix:
     also sweep slots that are `!mxfs_disklock_slot_live()` and not ours,
     on a slower cadence (~every 10th pass) so it costs ~3 reads/s on a
     32-node cluster, and treat a readable descriptor found there exactly
     like a pending one.
3. `v5_lease_expire_cb` stops calling `dead_node_notify_fn`; fences, notes,
   marks pending, wakes the coordinator.
4. `mxfs_v5_dlm_recovery_complete` stops calling `begin()`; it must look up
   the auth the coordinator published for that slot, verify ownership, then
   `advance(IMAGES_REPLAYED)`.
5. (folded into 2's gate) mount window must not take ownership.
6. GPT's reuse audit: `slot_unclaimed` (disklock.c:3014), the ADOPTED_SLICE
   mount path, journal-slice reuse — prove each honours stale-ACTIVE.
7. Rig cycle.

## Load-bearing facts confirmed this session

- Only caller of the five recovery ops in the whole tree is
  `mxfs_v5_dlm_recovery_complete`.  `refresh` and `takeover` had ZERO
  callers, which is why the API change was cheap — do the rest of the
  signature work now, before the coordinator adds callers.
- `mxfs_disklock_slot_live(ctx, slot)` (disklock.c:2531, prototype
  disklock.h:848) is the public per-slot liveness accessor; it returns true
  for `local_slot` unconditionally.
- `v5_node_is_dead(ctx, node)` (v5_mount.c:516) is the "fenced and retired"
  set — `v5_note_dead_node` is only ever called AFTER a successful fence, so
  membership in it is exactly GPT's "confirmed dead AND fenced" precondition.

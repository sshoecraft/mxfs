---
name: ccloop-c7ee71c6-sess132-landed-0.11.449-D1-fix-plus-escalation-plumbing
description: sess132 landing: 0.11.449 srcversion 9289F846B404D709E920557 — D1 blocker fixed (fallback drain deleted) + the caw/v5 escalation + membership plumbin…
metadata:
  type: reference
tags: [mxfs, dlm-caw, sess132, landing, 0.11.449, blocker3, escalation]
---

# sess132 landing — 0.11.449

`VERSION` **0.11.449**, srcversion `9289F846B404D709E920557`, builds clean (no
errors, no new dlm warnings; the xfs/ fork's pre-existing `struct iomap` /
`_mxfs_ioend_bioset_compat` / `mxfs_dir_addname_coherent_refresh` warnings are
unchanged). Fleet still on 0.11.440. **STILL STOP-SHIP.**

The ruling this implements is
`ccloop-c7ee71c6-sess132-GPT-ruling-steps1-4-DEFECTS-plus-step5`. Read that
first — it lists 5 defects in the sess131 landing, of which only D1 is fixed
here.

## 1. D1 FIXED — the fallback drain is gone

`caw_owed_worker_fn`'s park on `drain_armed` was bounded at
`QUIESCE_MS + DRAIN_MS` and drained anyway on expiry. Because phase 2's quiesce
is unbounded, that expiry could fire with `ops_active != 0`, the BAST producers
still live, and phase 4 not yet run — the worker would drain the pre-release
obligation set, exit, and leave phase 4's `release_all` publishing into a
registry with NO COLLECTOR. Uncollectable-by-construction residue, i.e. exactly
the bug the restructure exists to remove.

The wait is now unconditional. Verified there is no deadlock to protect
against: stop() arms the drain (phase 5) and joins the worker in that order on
the SAME thread, so if the arm never happens the join never happens either, and
a worker parked forever blocks nobody. `P256-DRAIN-UNARMED` is deleted with it.

Audited while doing this: `running = false` is written at dlm_caw.c 10590
(create, pre-thread), 10802 and 10828 (start-failure unwinds, both before or
without a live owed worker), and 11029/11034 (stop phase 1). So the only way to
reach the `!ctx->running` early return with a live parked worker is a CONCURRENT
stop — which is ruling defect D2, still open.

## 2. The escalation + membership plumbing (inert — no trigger calls it yet)

- `dlm_caw.h`: ctx fields `mship_view` / `mship_members`, lreq_lock-guarded,
  with the rationale for NOT calling a local counter an epoch (the real
  committed epoch, `struct mxfs_mepoch_rec`, belongs to net2, whose objects are
  not in the module Kbuild).
- `dlm_caw.h/.c`: `mxfs_dlm_caw_set_owed_stuck_fn(ctx, fn, data)` and
  `mxfs_dlm_caw_set_membership(ctx, view, members)`. The stuck-fn setter
  **refuses to register once `ops_closed`** so a late registration cannot hand a
  live callback to a context teardown already owns.
- `v5_mount.h`: `mxfs_v5_dlm_stuck_notify_fn` typedef + setter, carrying the
  handler contract GPT demanded — may run in the owed worker's context, so it
  must QUEUE and return (a synchronous path back into `mxfs_dlm_caw_stop` would
  join the calling thread), must be idempotent/once-only, must hold a mount
  lifetime reference, must be cancellable without self-deadlock, and is a
  notification of a decision already recorded, never the latch.
- `v5_mount.c`: `dlm_stuck_notify_fn/_data` + `mship_view` on `struct
  mxfs_v5_dlm`; `v5_owed_stuck_cb` forwards caw → xfs;
  `mxfs_v5_dlm_set_dlm_stuck_notify` registers with the CAW layer only when an
  upper handler exists; `v5_membership_beacon_caw` bumps the view and pushes
  `(view, count)` down on every CAW membership change.

## 3. Verified in-tree (answers GPT part 3D's ordering demand)

`xfs_do_force_shutdown` publishes the shutdown flag BEFORE withdrawing:
`xfs_set_shutdown(mp)` at `xfs/xfs_fsops.c:511`, then
`mxfs_dlm_shutdown_withdraw(mp)` at `:529`. So routing the escalation through
`xfs_force_shutdown(mp, SHUTDOWN_META_IO_ERROR)` — rather than calling the
withdraw directly — gives the required "stop mutating before we stop
advertising liveness" order.

## NOT DONE

Every trigger. No caller invokes `owed_stuck_fn`; no threshold constant exists;
the drain budget is untouched (still the flat 2000ms with the shared deadline
handed to each dispatch). Ruling defects D2, D3, D4, D5, D6 are all open, and
D2 is a blocker. The XFS-side handler (`mxfs_v5_dlm_set_dlm_stuck_notify` call
in `mxfs_dlm_cache_init`, plus a queued work fn) is unwritten.

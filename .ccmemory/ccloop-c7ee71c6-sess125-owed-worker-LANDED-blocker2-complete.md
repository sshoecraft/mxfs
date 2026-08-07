---
name: ccloop-c7ee71c6-sess125-owed-worker-LANDED-blocker2-complete
description: sess125: the OWED WORKER is LANDED (0.11.442, srcversion B2E4583…) — blocker 2's collector half is complete. Still STOP-SHIP, unreviewed, not deploye…
metadata:
  type: reference
tags: [mxfs, dlm-caw, lreq-registry, sess125, blocker2, owed-worker, stop-ship]
---

# sess125 — the owed-cleanup worker is written; blocker 2 is code-complete

Build: VERSION `0.11.441` → **`0.11.442`**. srcversion
`40C1AA02000E86B0240C748` → **`B2E4583BA40413F3B2704D2`**. `make modules`
exits 0; no `error:`, no new warnings (the one `mxfs_dlm_lkt_dump`
missing-prototype warning is pre-existing in `dlm/dlm.c`, not this work).

**STILL STOP-SHIP. Fleet stays on 0.11.440. Not deployed, not reviewed, not
rig-verified.** This closes the *writing* of blocker 2, not the defect.

## What landed

### `dlm/dlm_caw.h`
- **Added** `uint32_t lreq_sweep` (rotating sweep start, guarded by
  `lreq_lock`) next to `owed_worker`.
- **Deleted** `lreq_clrwait_ok` / `lreq_clrwait_to` and
  `MXFS_CAW_LREQ_CLRWAIT_MS` / `_STEP_MS` — the sess117 last-leaver park is
  gone. (Verified: no other reference anywhere in the tree.)

### `dlm/dlm_caw.c` — the worker block, placed after `caw_drop_own_waiter`, before `lreq_finish`
- `caw_owed_resolve()` — wraps `find_slot`; `-ENOENT` is the terminal proof.
  Allocates a real `mxfs_caw_lock_slot` for `data_out` and a real `uint32_t`
  for `empty_out` (`find_slot_skip` dereferences both unconditionally).
- `caw_owed_dispatch()` — snapshots resource/mask/w/wx/hint/**gen0** under the
  lock, resolves canonically, then one `caw_drop_own_waiter` pass per owed
  holder mode from the SNAPSHOT mask (so a mode is attempted at most once per
  dispatch), or one `MXFS_LOCK_NL` pass if only waiter bits are owed. Passes
  the freshly-read flags as the intent so a retry cannot re-inflate the record
  to maximal. `-ENOENT` → `lreq_owed_retract(..., terminal=true)` against
  gen0. Other resolve errors → P252-OWED-RESOLVE, obligation stands. Breaks
  the mode loop on a hard error but not on `-EAGAIN`/`-EBUSY` (contention).
  `self_joined = false` throughout.
- `caw_owed_release()` — clears `owed_busy`, drops `pin`, arms exponential
  backoff (`BACKOFF_MS << min(fails,7)` clamped to `BACKOFF_MAX_MS`),
  bumps `lreq_owed_stuck` **only on the exact crossing** of `_ESCALATE` (so it
  counts obligations, not log lines), P253-OWED-STUCK ratelimited. Every
  logged field is captured into locals BEFORE `lreq_gc`, which may free `e`.
- `caw_owed_count()` — teardown reporting only.
- `caw_owed_sweep(ctx, drain)` — **CLAIM-THEN-DISPATCH**, not
  walk-and-dispatch: one locked pass claims up to `_DISPATCH_MAX` entries into
  a stack array (`owed_busy = true`, `pin++` — exactly what makes `lreq_gc`
  refuse to free them), then unlocked dispatch+release per entry. The chain
  cannot be walked across an unlocked dispatch. Claim predicate skips
  `owed_busy`, skips `clr_active` (another local thread is already mid-CAS on
  those bits; closing its window broadcasts and brings us back), requires
  `lreq_owed_pending`, honours `owed_next_ms` unless draining. `lreq_sweep` is
  left AT the bucket where the quota ran out, so a partially consumed bucket
  resumes rather than being skipped.
- `caw_owed_worker_fn()` — sweep, then park on `lreq_cond` for `_BUSY_MS`
  (productive sweep) or `_IDLE_MS`, re-testing `ctx->running` under the lock
  the wakers broadcast under. After `!running`: drain loop with backoff floors
  ignored, bounded by `_DRAIN_MS` in `_DRAIN_STEP_MS` steps; residue reported
  as P254-OWED-TEARDOWN with `lreq_owed_left`.

### `lreq_finish` — converted
Both collectors deleted: the CLRWAIT park (and its P249) and the entire inline
owed run (the sess116 `e=NULL` corruption path, which also charged an
unbounded contended CAS loop to an XFS thread and simply did not exist for a
resource whose attempts had all already left). What remains: publish tenure +
`pub_seq++`, drop `attempts`/`writers`, read `lreq_owed_pending` BEFORE
`lreq_gc`, broadcast if owed. `resource` is now unused → `(void)resource;`
(signature kept; 5 call sites unchanged).

### Start / stop
- `mxfs_dlm_caw_start`: creates `owed_worker` when `ctx->lreq && lreq_lock &&
  lreq_cond`, **and FAILS THE START if it will not start** — unwinding
  `bast_poll_thread` first (`running = false`, signal `stop_cond`, join).
  Rationale written at the site: it is the only collector, and mounting
  without it is mounting an FS that can permanently wedge its peers.
- `mxfs_dlm_caw_stop`: broadcasts `lreq_cond` and joins `owed_worker` FIRST,
  before the BAST threads, so the drain's slot I/O runs while the transport
  is still up.

## Next session's first job

Blocker 2 is written but **NOT reviewed**. Per RULE 5 the next step is a GPT
consult on the worker itself before any rig cycle — it is a new kthread doing
destructive CAW I/O, and the last four rulings each found real defects in the
preceding session's landing. Specific things to put in front of it:

1. Is `-ENOENT` from `find_slot` genuinely terminal under a concurrent peer
   claim (the "unbroken chain of live-or-tombstone slots" invariant)?
2. The claim-then-dispatch array: entries are pinned but the CHAIN can be
   mutated by other threads between claim and release — that is fine for the
   claimed pointers, but is anything else assuming chain stability?
3. `caw_owed_dispatch` snapshots `gen0` and then `caw_drop_own_waiter`
   internally merges the intent (bumping `owed_gen`) and retracts against its
   OWN gen. Only the terminal path uses the dispatch's `gen0`. Is that split
   correct, or can the terminal retraction erase an intent published between
   the snapshot and the resolve?
4. Start-failure unwind ordering, and the 2s worst-case added to unmount.

Then: the sess113 debugfs exerciser is still the closure test for
D-SAMENODE-WAITER-CANCEL-COLLISION — a green board CANNOT close it (sess111
measured the reconcile arm entered 0 times on all 32 nodes).

## Method notes (carried forward, still true)

- `make modules 2>&1 | grep | head` MASKS hard failures — redirect to a file,
  check `$?`, then grep.
- Use the Edit tool with text copied from a Read; multi-line python
  `str.replace` against this file is fragile on tab depth.

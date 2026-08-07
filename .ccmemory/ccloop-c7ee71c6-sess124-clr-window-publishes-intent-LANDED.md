---
name: ccloop-c7ee71c6-sess124-clr-window-publishes-intent-LANDED
description: sess124: publication moved INTO lreq_clr_begin (find-or-create covers e==NULL) + caw_slot_clearing owes the divergence bits. srcversion 40C1AA0… Work…
metadata:
  type: reference
tags: [mxfs, dlm-caw, lreq-registry, sess124, blocker2, owed-worker, stop-ship]
---

# sess124 — publication is now atomic with the clear window

Build: VERSION `0.11.441`. srcversion `2C6F2B264DAA72AFF5A05B0` →
**`40C1AA02000E86B0240C748`**. `make modules` exits 0; no `error:`, no source
warnings. **STILL STOP-SHIP — fleet stays on 0.11.440.** Not deployed.

## What landed in `dlm/dlm_caw.c`

1. **`lreq_clr_begin` / `_begin_wait` gained `const struct mxfs_caw_owed_intent
   *intent` and a `uint64_t *gen0` out-param.** The intent is merged, `owed_gen`
   bumped, and `*gen0` returned inside the SAME `lreq_lock` section that does
   find-or-create + `clr_active++` + `pin++` + `pub_seq` snapshot. Broadcasts
   `lreq_cond` after unlocking when `intent != NULL`. New arg order:
   `(ctx, resource, intent, pub_seq0, gen0, out[, deadline_ms])`.
2. **`caw_slot_clearing` gained `uint8_t owed_mode`** and now publishes+retracts.
   `diverg-lo` / `diverg-hi` pass `our_mode` (nothing else in the file collects
   that bit — the give-up path reconciles the REQUESTED mode); `convert-downgrade`
   passes `MXFS_LOCK_NL` (an abandoned downgrade leaves the HIGHER mode held,
   which is the safe direction). Retraction builds a degenerate plan
   `{holder:true}` with `proven = (rc == 0)`.
3. **Unlock window and force-release window pass `intent = NULL`, deliberately**,
   with the reasons written at both sites: a failed release leaves the lock HELD
   so `tenure[]` still covers the bit (owing it yields only `holder_moot` churn);
   force-release has no single mode to owe and is itself the reclaim of record.
4. **`caw_drop_own_waiter` gained `const struct mxfs_caw_owed_intent *want`**
   (NULL ⇒ the maximal give-up intent, as before; the worker will pass what it
   is actually collecting so a pass cannot re-inflate the record to maximal).
   Publication moved OUT of the top-of-function block and INTO the
   `lreq_clr_begin_wait` call, and **the window now opens BEFORE `lreq_plan`**,
   because the plan's "nothing permitted" exit is one of the exits that must be
   covered. New local `owed = clr ? clr : e` is the retraction target — that is
   what closes the `e == NULL` gap (a claim-exhaustion give-up that never
   registered now gets its obligation recorded on the entry find-or-create
   makes). The alloc-failure and nothing-permitted exits now `lreq_clr_end`.
   All 5 call sites pass `NULL`.

## Still UNWRITTEN — the worker (next session's first job)

Unchanged from ccmemory `ccloop-c7ee71c6-sess123-blocker2-publish-retract-LANDED`
except that item "move publication into lreq_clr_begin" is now DONE:

- `caw_owed_resolve()` — wraps `find_slot`; **`-ENOENT` is the terminal proof**.
  NOTE: `find_slot_skip` dereferences `data_out` and `empty_out` unconditionally,
  so both must be real buffers, never NULL.
- `caw_owed_dispatch()` — snapshot the record under lock, resolve the slot, then
  one `caw_drop_own_waiter` pass per owed holder mode (track a `tried` mask so a
  failing mode is not retried within one dispatch), or one `MXFS_LOCK_NL` pass if
  only waiter bits are owed. Pass the freshly-read owed flags as the intent.
- `caw_owed_sweep(ctx, bool drain)` — rotating bucket start (needs a new
  `uint32_t lreq_sweep` in `dlm_caw.h`), claim under lock with
  `!owed_busy && !clr_active && lreq_owed_pending && (drain || now >= owed_next_ms)`,
  set `owed_busy` + `pin++` BEFORE unlocking, `_DISPATCH_MAX` per sweep. On
  release: clear `owed_busy`, `pin--`, and if still pending bump `owed_fails` +
  exponential `owed_next_ms` (`_BACKOFF_MS << min(fails,7)` clamped to
  `_BACKOFF_MAX_MS`), P253-OWED-STUCK at `_ESCALATE`. **`lreq_gc` may free `e` —
  capture anything you want to print into locals BEFORE calling it.**
- `caw_owed_worker_fn()` — own kthread; park on `lreq_cond` for
  `_BUSY_MS`/`_IDLE_MS`; after `!ctx->running`, a final drain sweep loop bounded
  by `_DRAIN_MS` in `_DRAIN_STEP_MS` steps with backoff floors ignored; residue
  as P254-OWED-TEARDOWN (`lreq_owed_left`).
- Place the worker block AFTER `caw_drop_own_waiter` ends and BEFORE
  `lreq_finish` (it calls the former; `mxfs_dlm_caw_start` at the bottom of the
  file sees it fine).
- `lreq_finish`: delete the CLRWAIT park and the whole inline owed run (the
  sess116 `e=NULL` corruption path); it becomes publish-tenure, drop attempts,
  `lreq_gc` (which already refuses while anything is owed), broadcast if owed.
  Then delete `MXFS_CAW_LREQ_CLRWAIT_MS/_STEP_MS` and `lreq_clrwait_ok/_to`
  from the header.
- Start/stop: create `ctx->owed_worker` in `mxfs_dlm_caw_start` when `ctx->lreq`;
  **fail the start** if it will not start, joining `bast_poll_thread` on that
  error path (`ctx->running = false` + `mxfs_pal_cond_signal(ctx->stop_cond)`
  first). `mxfs_dlm_caw_stop` broadcasts `lreq_cond` and joins `owed_worker`
  before the bast threads.

## Method notes

- `make modules 2>&1 | grep | head` MASKS hard failures — redirect to a file,
  check `$?`, then grep.
- Multi-line `str.replace` in python against this file is fragile (tab depth);
  use the Edit tool with text copied from a Read.

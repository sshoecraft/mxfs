---
name: ccloop-c7ee71c6-sess127-blockers-5-and-6-LANDED
description: sess127: sess126 ruling blockers 5 (collector re-publication) + 6 (condvar lost wakeup) LANDED on 0.11.443, builds clean. 5 blockers remain. Still ST…
metadata:
  type: reference
tags: [mxfs, dlm-caw, sess127, owed-worker, blocker5, blocker6, stop-ship]
---

# sess127 — sess126 ruling blockers 5 and 6 LANDED

Tree **0.11.443**, srcversion `553D71764CC3A48DB29E670`, builds clean (only
the two pre-existing warnings: compiler-differs, `dlm.c:259` missing
prototype). **NOT deployed.** Fleet still on 0.11.440. **STILL STOP-SHIP** —
5 of the 7 sess126 blockers remain open.

Landed in the order the ruling prescribed (5 + 6 first: smallest, purely
inside the worker).

## Blocker 5 — the collector republished obligations it already owned

Root: `caw_owed_dispatch` handed the flags it had just read back down to
`caw_drop_own_waiter` as `want`, and `want`'s ONLY effect was
`lreq_clr_begin_wait(..., &intent, ...)` → `lreq_owed_merge` → **an
unconditional `owed_gen++` once per mode**. `owed_gen` is the token every
retraction validates against, so a concurrent local clear that genuinely
proved its bits clear would find `owed_gen != gen0`, refuse, and re-owe work
already done.

Fix, three parts:

1. **`lreq_clr_begin_existing(ctx, e, &gen0)`** (new, above `lreq_clr_end`).
   Raises `clr_active`/`pin` and snapshots `owed_gen` under `lreq_lock` —
   same exclusion as `lreq_clr_begin`, no merge, no gen bump. Cannot fail
   and never touches the reserve: `e` is already held live by the sweep
   claim, so the sess120 allocation-free requirement is satisfied vacuously.
2. **`caw_drop_own_waiter`'s `const struct mxfs_caw_owed_intent *want`
   parameter is GONE**, replaced by `bool collector`. It had exactly two
   callers (both in the worker); the three give-up sites all passed NULL and
   now pass `false`. `collector=true` takes the `lreq_clr_begin_existing`
   arm and builds no intent at all.
3. **Per-mode re-read** (the ruling's second half of blocker 5). The mode
   loop now re-reads `owed_holder_mask`/`owed_waiters`/`owed_waiters_ex`
   under the lock before EACH mode and intersects with the top-of-dispatch
   snapshot mask. Bound is preserved (a mode is still attempted at most once
   per dispatch, so a hot resource cannot pin the worker), and two new exits
   appear: `break` when nothing is owed any more (a first mode that went
   terminal no longer does I/O for every remaining bit of a dead snapshot),
   `continue` when that specific mode was discharged concurrently.

Side effect worth knowing: `lreq_owed_merge` also did `owed_next_ms = 0`, so
the old collector reset its own backoff every pass. It no longer does. That
is correct and is half of what blocker 7's surviving part asks for.

## Blocker 6 — condvar lost-wakeup window

Root: every broadcast is issued OUTSIDE `lreq_lock` (deliberate — the wakee
would otherwise block on a mutex the waker holds), and the worker did an
UNCONDITIONAL `cond_timedwait` after reacquiring. A publication landing in
"decided to park" → "parked" signals an empty condvar and is lost; the
obligation then waits out `IDLE_MS=1000`.

Fix:

- **`ctx->lreq_owed_work_seq`** (new, `dlm_caw.h`, guarded by `lreq_lock`),
  bumped inside the same critical section as every runnable-making event:
  `lreq_owed_merge` (publication), `lreq_clr_end` (a window closing can
  un-skip an entry the sweep passed over), `lreq_finish` when `owed` (a
  departure can turn a refused plan permissive), and `mxfs_dlm_caw_stop`.
- **`caw_owed_sweep(ctx, drain, &seq0, &next_due)`** — `seq0` is read INSIDE
  the same locked walk that chooses the claim set, so there is no gap to
  sample it in. The park predicate is
  `running && seq0 == ctx->lreq_owed_work_seq`.
- **`next_due` replaces the fixed BUSY_MS/IDLE_MS cadence.** 0 = nothing
  owed (park IDLE_MS); `<= now` = ready now (park BUSY_MS as a yield);
  `> now` = the earliest backoff floor, capped at IDLE_MS. Fed from three
  places: entries skipped for backoff during the walk, `capped = true` when
  the dispatch cap cut the walk short (backlog unexamined → due = 1), and
  **`caw_owed_release` now RETURNS the re-armed `owed_next_ms`** — those are
  set after the locked walk and would otherwise be slept past.
  Entries skipped for `clr_active` are deliberately NOT counted as due —
  `lreq_clr_end`'s seq bump covers them; a timer would spin for the whole
  duration of somebody else's CAS loop.
- **`mxfs_dlm_caw_stop` now sets `running = false` INSIDE `lreq_lock`** (with
  a no-registry fallback) and bumps the seq there. Same lost-signal shape as
  a publication, and it supplies the release/acquire pairing `volatile bool`
  alone does not — which is what the ruling's "READ_ONCE/WRITE_ONCE or
  atomic" point actually needs here.

## What is STILL OPEN (5 of 7)

Per the ruling's landing order, next is **blocker 1** (widest edit):
absolute deadline plumbed through `sweep → dispatch → resolve →
drop_own_waiter → find_slot`, checked before each claim, mode, slot read,
CAW and retry sleep; replace the 1000-attempt counter with a time budget;
`OWED_DONE/RETRY/DEADLINE/FATAL` return. `DRAIN_MS` is still checked only
BETWEEN sweeps — I documented that explicitly in the worker comment so it is
not mistaken for a bound.

Then **4** (owed-ready queue), then **2 + 3** together (producer quiescence
ordering + terminal withdrawal — one lifecycle change).

**Blocker 7 still needs the verification the ruling asked for** against
`lreq_owed_retract` (`owed_fails = 0; owed_next_ms = 0` when not pending) —
I did not get to it. The surviving half (`owed_since_ms` tracked separately
so continuous publication cannot suppress blocker 3's wall-clock escalation)
belongs with blocker 3.

Also still owed from the ruling's non-blocking list: preallocate the
worker's slot buffer at thread start (`caw_owed_resolve` allocates per
pass — a cleanup mechanism blockable by `-ENOMEM` is wrong), atomics on
`lreq_owed_disp`/`lreq_owed_runs`, the `hint` snapshot cleanup, exit-time
lifecycle assertions, and the ruling item 1 ACTION: fix the overclaiming
comment at `dlm_caw.c:3616-3622` and audit every local bit-setting site for
live-attempt/tenure/published-obligation coverage.

Closure for D-SAMENODE-WAITER-CANCEL-COLLISION still requires the sess113
debugfs exerciser — a green board CANNOT close it.

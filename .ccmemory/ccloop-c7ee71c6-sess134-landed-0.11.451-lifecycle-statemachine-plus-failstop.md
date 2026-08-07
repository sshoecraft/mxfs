---
name: ccloop-c7ee71c6-sess134-landed-0.11.451-lifecycle-statemachine-plus-failstop
description: sess134 landing: 0.11.451 srcversion AA5317A2F0970AA56BAB4BF — D2/D3/D4/D6 all implemented: lifecycle state machine, D3 release term, bounded teardow…
metadata:
  type: reference
tags: [mxfs, dlm-caw, sess134, landing, 0.11.451, lifecycle, fail-stop, D2, D3, D4, D6]
---

# sess134 landing — 0.11.451

`VERSION` **0.11.451**, srcversion `AA5317A2F0970AA56BAB4BF`, builds clean.
Warning set is the pre-existing baseline exactly (xfs/ fork: xfs_super.c
`xfs_fs_report_error`, xfs_buf.c missing-prototypes / frame-size / `"/*" within
comment`; dlm/: dlm.c `mxfs_dlm_lkt_dump`, disklock.c frame sizes). **No new
warnings.** Fleet still on 0.11.440. STILL STOP-SHIP — nothing verified on the
rig yet.

Implements ALL FOUR items of the sess133 NOT-DONE list. Read
`ccloop-c7ee71c6-sess133-GPT-ruling-D2-D4-statemachine-plus-FAILSTOP` first.

## 1. The lifecycle state machine (D2/D4) — dlm_caw.{c,h}

- `ctx->lc` (`enum mxfs_caw_lifecycle`) added, guarded by `lreq_lock`.
  `stop_ran` DELETED — the state supersedes it.
- `start()`: NEW → STARTING → RUNNING, or → **START_FAILED** on either unwind
  (not back to NEW: a failed start may hold published residue, and the
  mount-time own-slot reclaim already ran, so it must not be presumed clean).
  `caw_set_lc()` is the locked setter.
- `stop()`: **owner election** at the top. STOPPING ⇒ cond-wait for the owner;
  STOPPED or still-STOPPING-after-the-wait ⇒ return, leaving the owner's stored
  verdict untouched. NEW/STARTING/RUNNING/START_FAILED all converge on ONE
  teardown body (ruling A3). The election critical section also does
  `ops_closed = true`, `running = false`, `release_all_done = false`,
  `lreq_owed_work_seq++`, and **snapshots `release_on_stop` into `release_now`**
  so teardown cannot see two answers in two phases.
- Phase 6 stores the COMPLETE verdict, THEN sets `lc = STOPPED`, both in one
  critical section, and broadcasts after unlocking (ruling A2's exact order).
- `mxfs_dlm_caw_departed_clean()` / `_unsafe_to_free()` now read under
  `lreq_lock` — **signature changed, `const` dropped** (one external caller,
  v5_mount.c:4122; unaffected).
- `destroy()` reads the leak decision via the locked accessor and states the
  SINGLE-DESTROY contract explicitly (serialising stop() does not serialise
  destroy(); a refcount is the fix if a second caller ever appears).

**`caw_op_enter` — DO NOT "tighten to lc == RUNNING".** The sess133 note said
that and it is WRONG: `mxfs_dlm_caw_purge_dead_nodes_ex` (a gated entry point)
runs at v5_mount.c:3728, i.e. BETWEEN create() and start(), so `lc == RUNNING`
refuses it and breaks every mount. The landed predicate is
`(lc == NEW || STARTING || RUNNING) && !ops_closed` — still strictly TIGHTER
than the old `!ops_closed`, because START_FAILED now refuses.

## 2. D3's release term — phase 6

    clean = quiesced && !teardown_expired && !owed_failed &&
            left == 0 && rel_lost == 0 &&
            (release_now ? release_all_done : held_at_stop == 0)

- `release_all_done` is set ONLY at the final exit of `caw_release_all_body`,
  so it means the traversal FINISHED (its NULL-ctx and alloc-failure exits leave
  it false). Cleared at election so a prior `mxfs_dlm_caw_release_all` (mount.c
  :2724) cannot pre-satisfy it.
- `held_at_stop` snapshotted under `held.lock` BEFORE `lreq_lock` (never the
  reverse order — every acquire path takes them held→lreq).
- P259-DEPART-UNCLEAN now prints `expired= released= rel_done= held=`.

## 3. D6 — the bounded teardown and the fail-stop

- **ONE ABSOLUTE deadline for the whole teardown**, not per phase:
  `t0 + MXFS_CAW_QUIESCE_MS` (155s) is the escalation point, `+ grace` is the
  mandatory fail-stop. A bound that resets per phase is not a bound, and phases
  2, 3 and 5 all block.
- `caw_teardown_expire_locked()` — sticky latch: sets `unsafe_to_free` FIRST
  (that is what makes the deferred item's bare ctx pointer safe — destroy will
  leak rather than free), `teardown_expired` + ms, `caw_owed_fail_latch`, and
  returns whether to queue the one-shot escalation.
- `caw_teardown_escalate_queue()` → `mxfs_pal_defer(caw_teardown_escalate_work,
  ctx)`. **The quiesce loop only records and queues; it never invokes the
  handler** (ruling B3). A negative return logs P261-ESCALATE-UNDELIVERED — the
  latch is the safety, the channel never is.
- Phase 2 enforces the terminal deadline ITSELF (the work item may never run)
  and calls `mxfs_pal_failstop` while NOT holding `lreq_lock`.
- `caw_join_bounded(ctx, &slot, what, esc_at)` replaces all three
  `mxfs_pal_thread_join` calls (bast_recv, bast_poll, owed_worker) **and the
  failed-start unwind join** — ruling A1's second hole. Shape: join_timeout to
  esc_at → latch+queue → join_timeout(grace) → fail-stop.
  P262-TEARDOWN-JOIN-STUCK / -LATE.
- `mxfs_caw_failstop_grace_ms` module param, default 45000, **clamped on read**
  to [5000, 300000] by `caw_failstop_grace_ms()` — the ruling forbids an
  infinite setting on a shared-write clustered mount.

## 4. dlm/mount.c err_dlm (:2507) — the sess133-found defect, FIXED

Now calls `mxfs_dlm_caw_set_release_on_stop(true)` before stop(). A FAILED mount
is not a withdrawn one: it has no frozen slice to protect and was leaving its
bits on the disk.

## THE OBJTOOL TRAP — cost half an hour, do not repeat

`__noreturn` on `mxfs_pal_failstop` produced
`objtool: caw_join_bounded() falls through to next function lreq_oq_sync()`.
objtool checks control flow against a HARDCODED noreturn list and cannot learn
about a function from another translation unit. **None of these work:** an
explicit `return;` (GCC elides it), `unreachable()` (the annotate_unreachable
machinery is gone on 6.8), or moving the call off the function tail (GCC sinks
the cold branch back to the end).

**What works, and is now in pal.h:** drop the attribute, rename the impl to
`mxfs_pal_failstop_fn` (both PAL backends + the EXPORT), and make
`mxfs_pal_failstop` a macro = `fn(...)` then `for (;;) mxfs_pal_cond_resched();`.
objtool accepts an unconditional self-branch as a valid end of flow, and the
spin is honest: it makes "never returns" true at the call site regardless of the
implementation.

## NOT DONE — next session

1. **The escalation chain still dead-ends.** `mxfs_v5_dlm_set_dlm_stuck_notify`
   has NO caller anywhere in-tree, so `ctx->dlm_stuck_notify_fn` is always NULL
   and `v5_owed_stuck_cb` returns immediately. The ruling's "asynchronously
   request force-shutdown" therefore does not actually happen yet. Wire the XFS
   end (it must QUEUE, not act — it can run in the owed worker's context).
2. RULE-5 re-consult on the landed shape before any rig cycle (sess133 item 4).
3. `mxfs_dlm_caw_create`'s stop_lock/stop_cond failure unwind (~dlm_caw.c:10754)
   still leaks `mem_locks`, `held.slots`, `mem_lock_mutex`, `slot_hints`,
   `grant_meta`, `orphan_clock`, the lreq table and its reserve. Still open.
4. Nothing here is rig-verified. D2/D3/D4/D6 stay OPEN until a test exercises
   the cause (RULE 6).

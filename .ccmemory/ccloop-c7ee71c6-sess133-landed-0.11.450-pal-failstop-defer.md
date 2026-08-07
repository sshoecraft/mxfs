---
name: ccloop-c7ee71c6-sess133-landed-0.11.450-pal-failstop-defer
description: sess133 landing: 0.11.450 srcversion 9CAFBCBC6AC2B55EA8B1227 — PAL fail-stop + deferred-call primitives and the CAW lifecycle enum. NOT yet wired.
metadata:
  type: reference
tags: [mxfs, dlm-caw, sess133, landing, 0.11.450, pal, fail-stop, lifecycle]
---

# sess133 landing — 0.11.450

`VERSION` **0.11.450**, srcversion `9CAFBCBC6AC2B55EA8B1227`, builds clean (no
errors; the only warnings are the pre-existing xfs/ fork ones — xfs_super.c
`xfs_fs_report_error`, xfs_buf.c missing-prototypes / frame-size / `"/*" within
comment`, dlm.c `mxfs_dlm_lkt_dump`, disklock.c frame sizes — all unchanged).
Fleet still on 0.11.440. **STILL STOP-SHIP.**

Implements the enabling half of
`ccloop-c7ee71c6-sess133-GPT-ruling-D2-D4-statemachine-plus-FAILSTOP`. Read that
ruling first.

## What landed

**`pal/pal.h` + `pal/linux/kern.c` + `pal/linux/user.c` — two new primitives.**
The dlm/ layer may not touch a kernel API directly (architectural invariant 4),
and it needed both of these, so they had to be PAL additions:

- `mxfs_pal_failstop(fmt, ...)` — `__noreturn`. Kernel: `pr_emerg` the message
  first (so it reaches remote syslog even if the panic output does not), then
  `panic()`. User: `abort()`. This is ruling B1's non-returning local
  fail-stop; the header carries the full rationale, including WHY the two
  alternatives were rejected (permanent kernel hang / a use-after-free on the
  VFS-freed `mp`).
- `mxfs_pal_defer(fn, arg)` — one-shot deferred call, ruling B3. Kernel: a
  self-freeing `work_struct` on `system_unbound_wq` (unbound so a blocked
  handler cannot starve other items), `GFP_ATOMIC` because callers hold
  teardown locks. User: a detached pthread. Returns 0 only when queued; the
  caller must treat a negative return as UNDELIVERED, since the notification is
  a channel and never the latch.
- Both exported (`EXPORT_SYMBOL_GPL`) alongside the other PAL symbols.

**`dlm/dlm_caw.h` — `enum mxfs_caw_lifecycle`** (NEW / STARTING / RUNNING /
START_FAILED / STOPPING / STOPPED) with the D2 defect statement and the
transition diagram in its comment, including why `running` could not encode it
and its demotion to a pure loop-exit hint. **Declared only — no ctx field, no
transitions, nothing reads it yet.**

## Verified in-tree this session (settles ruling A1's deadlock question)

The escalation → withdraw → re-entrant-stop deadlock GPT warned about does NOT
exist in the current call graph, so `mxfs_dlm_caw_stop_try()` is NOT needed yet:
`xfs_do_force_shutdown` → `mxfs_dlm_shutdown_withdraw` (xfs_mxfs_dlm.c:26388)
only `schedule_work(&mp->m_mxfs_withdraw_work)`, whose fn calls
`mxfs_v5_dlm_shutdown_withdraw`, and that function sets `ctx->withdrawn = true`
and calls `mxfs_disklock_withdraw` — **it never calls `mxfs_dlm_caw_stop`**.
Write that as an invariant when the trigger lands, or a future change
reintroduces the deadlock silently.

Also confirmed the PAL already has the exact bounded-join shape ruling B1
demands: `mxfs_pal_thread_join_timeout` waits on the `exited` completion (which
`kthread_fn_wrapper` signals as its last act) and only then does
`kthread_stop` + free. So phases 3/5 do NOT need a new primitive — just the
switch from `mxfs_pal_thread_join` to the timed form plus a fail-stop on expiry.

## NOT DONE — next session, in order

1. `ctx->lc` field + transitions in create/start/stop/destroy; owner election on
   `→ STOPPING`; waiters cond-wait for STOPPED and read the STORED verdict
   under `lreq_lock`; `caw_op_enter` tightened from `!ops_closed` to
   `lc == RUNNING`; delete `stop_ran` (the state supersedes it).
2. D3's release term:
   `release_on_stop ? (release_all traversal COMPLETED && rel_lost == 0)
                    : (held_count_snapshot == 0 && census_left == 0)`,
   with `held.count` snapshotted under `held.lock` BEFORE `lreq_lock` is taken,
   and `release_on_stop` snapshotted so it cannot change during teardown.
3. D6: phase 2 bounded at QUIESCE_MS (155s) = escalation threshold, not
   abandonment — latch `quiesce_expired`, `mxfs_pal_defer` the notify ONCE,
   then one bounded grace (30–60s, module param, NOT settable to infinite);
   grace expiry ⇒ `mxfs_pal_failstop`. Same deadline+fail-stop on the phase 3
   and phase 5 joins and on the failed-start unwind.
4. Then step 5's triggers, then re-consult before any rig cycle.

## Also found, not yet fixed (log them so they are not lost)

- `mxfs_dlm_caw_create`'s stop_lock/stop_cond failure unwind (dlm_caw.c
  ~10754) frees only `held.lock` and `ctx` — it leaks `mem_locks`,
  `held.slots`, `mem_lock_mutex`, `slot_hints`, `grant_meta`, `orphan_clock`,
  the lreq table and its reserve entries. OOM-path leak, unreachable in
  practice, still a defect.
- `dlm/mount.c:2507` (the `err_dlm` mount-failure path) calls
  `mxfs_dlm_caw_stop` WITHOUT `set_release_on_stop(true)`, so a failed mount
  suppresses its own release and leaves whatever bits it took on the disk. The
  normal teardown at :2783 does set it. That path is not withdrawn — it should
  release.

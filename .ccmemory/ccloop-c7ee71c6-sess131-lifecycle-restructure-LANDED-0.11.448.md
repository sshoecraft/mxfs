---
name: ccloop-c7ee71c6-sess131-lifecycle-restructure-LANDED-0.11.448
description: sess131: sess130 ruling steps 1-4 LANDED on 0.11.448 — admission gate, stop() restructure, release_all publication, v5 clean-departure gate. Step 5 r…
metadata:
  type: reference
tags: [mxfs, dlm-caw, sess131, blocker2, blocker3, lifecycle, teardown, departed-clean]
---

# sess131 — the sess130 lifecycle restructure, steps 1–4 LANDED

Tree **0.11.448**, srcversion `4D9260470F745DF49F1B7CD`, builds clean (only the
pre-existing `mxfs_dlm_lkt_dump` missing-prototype warning). Fleet still on
0.11.440. **STILL STOP-SHIP** — step 5 (blocker 3 proper) is not written, and
D-SAMENODE-WAITER-CANCEL-COLLISION still needs the sess113 debugfs exerciser.

Continued D-SAMENODE-WAITER-CANCEL-COLLISION (ledger #16), same reason as
sess119–130.

## What is now in the tree

**Step 1 — the admission gate (was already landed at 0.11.447, verified here).**
`caw_op_enter/leave` at dlm_caw.c ~4630/4649. 8 gated entry points, all as thin
wrappers over a `*_body` so no exit path can leak a count: lock, unlock_gen,
open_set, open_clear, force_release_self, convert, purge_dead_nodes_ex,
flush_held_to_disk. `unlock`, `purge_node`, `purge_dead_nodes` are pure
delegations and inherit the gate (verified line by line — do not "fix" them).
`P255-CAW-OPS-UNBALANCED` on an unbalanced leave.

**Step 3 — release_all publishes its failures.**
- `caw_owe_residue(ctx, resource, slot_hint)` — find-or-create the lreq entry and
  `lreq_owed_merge` a MAXIMAL intent (every holder mode + both waiter bitmaps).
  Returns false on a dry reserve.
- `caw_release_all_body(ctx, &owed, &lost)`; `mxfs_dlm_caw_release_all` is now a
  thin wrapper over it. Per slot: `cleared` is set ONLY by a CAS returning 0.
  Every other exit (read error, bad magic, 20 exhausted retries, hard CAS error)
  publishes. The resource is captured into a local `res` at the last GOOD read —
  NOT read back off `cur_slot` at the end, because a later failing `read_slot`
  may have scribbled the buffer and an obligation keyed on garbage is worse than
  none.
- `lost` = residue that could not be recorded at all (no resource / dry reserve).
  The alloc failure at the top counts EVERY tracked slot as lost
  (`P257-RELEASEALL-NOMEM`), per GPT's "must escalate, not log-and-continue".
- New P-lines: `P257-RELEASEALL-NOMEM`, `P257-RELEASEALL-LOST`,
  `P257-RELEASEALL-RESIDUE`.

**Step 2 — `mxfs_dlm_caw_stop` restructured into 6 phases.**
1 close admission (`ops_closed` + `running=false` + work-seq bump, one lreq_lock
section) → 2 quiesce on `ops_active == 0` → 3 join the BAST threads (the other
producers) → 4 EXCLUSIVE `caw_release_all_body`, gated by `release_on_stop` →
5 arm `drain_armed`, join the owed worker → 6 census with
`caw_owed_count_locked` and the verdict, in ONE critical section.

Design points that took work and must not be undone:
- **Phase 4 is NOT gated on `quiesced`.** Phase 2 exits only at
  `ops_active == 0`, so exclusivity holds however long it took. A late quiesce
  forbids the CLAIM (via the latch); skipping the release would leave strictly
  MORE bits on disk.
- **The quiesce wait is unbounded on purpose.** GPT ruling item 2: a timeout must
  not permit teardown to continue. At `MXFS_CAW_QUIESCE_MS` (155s, derived) it
  latches the failure, sets `unsafe_to_free`, logs `P258-QUIESCE-STUCK`, notifies
  once, and keeps waiting, re-logging every `MXFS_CAW_QUIESCE_GRIPE_MS` (30s,
  chosen to land several times before the kernel's 120s hung-task detector).
- **The phase-6 escalation deliberately does NOT notify.** It is post-join;
  ruling item 5's second half closes the channel there
  (`owed_stuck_fn = NULL` under lreq_lock). The recorded state is what carries
  the failure out — which is exactly why the state, not the callback, is the
  latch.
- `caw_owed_fail_latch(ctx)` (caller holds lreq_lock; returns true once on the
  transition) sets `owed_failed` + `owed_failed_ms` + `ops_closed` +
  `departed_clean = false`. `caw_owed_fail_notify(ctx)` (NO lock) re-reads the
  fn pointer under the lock so a cleared channel cannot be called into.
- `stop_ran` (new header field) distinguishes "never started" (departs clean by
  construction) from "already torn down" (verdict stands). destroy() always makes
  a second stop() call — without this it would overwrite a refusal with a vacuous
  pass.
- `mxfs_dlm_caw_destroy`: its unconditional `release_all` is DELETED (it ran
  after the worker join, so anything it published was uncollectable by
  construction, and it defeated the v5 D2 withdrawn-suppression). It now honours
  `unsafe_to_free` by leaking the ctx with `P260-CAW-CTX-LEAKED` rather than
  freeing under a live user.

**Step 4 — `mxfs_v5_dlm_shutdown` (dlm/v5_mount.c).**
- Its own `mxfs_dlm_caw_release_all` is gone; instead
  `mxfs_dlm_caw_set_release_on_stop(ctx->dlm_caw, !ctx->withdrawn)` +
  `mxfs_dlm_caw_stop()` EARLY, in that old slot — before the GOODBYE, with
  lease/discovery/heartbeat still up, because the drain does real slot I/O and
  needs this node still to be a live member.
- New local `depart_clean = !ctx->withdrawn && mxfs_dlm_caw_departed_clean(...)`,
  computed once and used by BOTH the GOODBYE broadcast and
  `mxfs_disklock_release_slot`. Both previously tested only `!ctx->withdrawn`.
- The later `mxfs_dlm_caw_stop` before destroy is removed (stop already ran).

**dlm/mount.c:2778** — the legacy/userspace teardown path had to add
`mxfs_dlm_caw_set_release_on_stop(mnt->dlm_caw, true)`, because
`release_on_stop` defaults FALSE (fail-closed) and destroy no longer releases.
Without it that path would silently stop releasing. `dlm/mount.c:2508` is a
mount-error unwind holding nothing — left at the default deliberately.

New public API in dlm_caw.h: `mxfs_dlm_caw_set_release_on_stop`,
`mxfs_dlm_caw_departed_clean` (NULL ctx ⇒ true: a TCP mount has no CAW bits to
account for), `mxfs_dlm_caw_unsafe_to_free`. New constant
`MXFS_CAW_QUIESCE_GRIPE_MS`. New field `stop_ran`.

## NEXT SESSION

1. **Step 5 — blocker 3 proper.** The runtime (non-teardown) escalation is still
   missing: derive `OWED_ESCALATE_MS` from `MXFS_CAW_WAIT_TIMEOUT_MS` /
   `MXFS_CAW_UNLOCK_DEADLINE_MS` (GPT rejected "5 minutes" as arbitrary), fire on
   BOTH triggers (runtime episode age via `owed_since_ms`, AND drain-deadline
   expiry with residue — note GPT's arithmetic that DRAIN_MS=2000 against
   PASS_MS=1000 admits only ~2 entries, so a queue of any depth withdraws even
   when every op would have cleared: that needs an answer, not just an
   escalation). Log line must carry the MEMBERSHIP EPOCH + node/mount identity +
   WHICH trigger fired, and must say "this resource has had continuously
   outstanding cleanup for X", not "these bits are X old" (episode-age
   attribution). Wire `owed_stuck_fn` caw → v5 → xfs → `mxfs_dlm_shutdown_withdraw`.
2. **A RULE-5 consult on the landed steps 1–4 before any rig cycle.** This is a
   large lifecycle change to the unmount path of every node; GPT found a real
   race in the last design and should see this one.
3. Only then a rig cycle. Watch for the new P-lines on a normal 32-node unmount:
   `P257-RELEASEALL-RESIDUE` / `P259-DEPART-UNCLEAN` firing routinely would mean
   the drain budget or the census is wrong, not that the FS is broken — diagnose
   before treating either as a defect.
4. Closure for D-SAMENODE-WAITER-CANCEL-COLLISION still requires the sess113
   debugfs exerciser. A green board CANNOT close it (sess111 measured the
   reconcile arm entered 0 times on all 32 nodes).

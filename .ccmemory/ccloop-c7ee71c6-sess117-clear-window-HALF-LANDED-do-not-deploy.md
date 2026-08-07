---
name: ccloop-c7ee71c6-sess117-clear-window-HALF-LANDED-do-not-deploy
description: sess117: the clear-window linearization is HALF-LANDED (clearer side done, builds clean, srcversion 3C6F0BF...) — publication side NOT wired. STOP-SH…
metadata:
  type: reference
tags: [mxfs, dlm-caw, lreq-registry, sess117, samenode-waiter, partial-landing, do-not-deploy]
---

# sess117 — clear-window linearization: CLEARER side landed, PUBLICATION side owed

**Tree state: VERSION still `0.11.441` (NOT revved — the landing is incomplete).
Built srcversion is now `3C6F0BF4547E9A22C95A0ED` (was `B385712E9A1F9A025F1D3C1`).
Builds clean; the ONLY two warnings are `lreq_clr_snap` / `lreq_clr_still_good`
"defined but not used", which is precisely the unwired half.
STILL STOP-SHIP. DO NOT BOARD, DO NOT DEPLOY. Fleet is on 0.11.440.**

Implements: `…sess116-clear-window-linearization-design` (which implements the
sess115 ruling). Fixes the corruption in
`…sess116-owed-run-passes-NULL-real-corruption`.

## What LANDED this session (all in `dlm/dlm_caw.c`, `dlm/dlm_caw.h`)

1. **The owed-run corruption is FIXED.** `lreq_finish`'s deferred pass now
   passes the pinned entry `e` instead of `NULL`, so `lreq_plan` no longer
   short-circuits to the legacy clear-everything plan. The full sequence is
   written into the block comment at the call site.
2. **`lreq_plan` gained `bool self_joined`.** The owed pass has ALREADY left,
   so it must not subtract itself from `attempts`/`writers` — passing `false`
   there was a second bug the `e = NULL` fix would otherwise have introduced
   (one live attempt would have read as zero). The three acquire/convert call
   sites pass `true`.
3. **`struct mxfs_caw_lreq` gained `clr_active` / `clr_seq` / `pub_seq`**, plus
   `struct mxfs_caw_clr_snap {seq, quiet, armed}`. `lreq_gc` now also refuses to
   free while `clr_active` is set.
4. **Four helpers written**: `lreq_clr_begin` (find-OR-CREATE, `clr_active++`,
   `pin++`, returns `pub_seq0`), `lreq_clr_end(committed)` (bumps `clr_seq`,
   broadcasts `lreq_cond`), `lreq_clr_snap`, `lreq_clr_still_good`. The long
   block comment above `lreq_clr_begin` carries the whole reduction argument.
5. **`caw_drop_own_waiter`** opens a window before its first slot read,
   **re-derives `lreq_plan` on every iteration** right before the CAS (the plan
   used to be evaluated once — a tenure published in the read/CAS gap was
   invisible to it), sets `committed` on a landed CAS, and closes the window
   after the owed re-record. Window-open failure with a registry present =
   REFUSE the clear and owe it (fail-closed).
6. **`mxfs_dlm_caw_unlock_gen`** opens a window next to `caw_release_mark(true)`
   and closes it at `out:` before dropping the mark; the early `-ESTALE` return
   closes it too. Open failure proceeds under the legacy mark and logs
   (refusing an unlock wedges the cluster — worse trade).
7. **`lreq_release_all` gained `pub_seq0`** and only retires `tenure[]` when
   `e->pub_seq == pub_seq0`; otherwise keeps it, bumps `ctx->lreq_rel_kept`,
   logs `P248-LREQ-REL-KEPT`.
8. **`lreq_finish` bumps `pub_seq`** with the tenure raise, and implements the
   design's blocker-6 wait: if this call takes the LAST attempt out while
   `clr_active != 0`, it waits on `lreq_cond` **before** decrementing, bounded
   by `MXFS_CAW_LREQ_CLRWAIT_MS` (50ms, 10ms steps), fail-forward on timeout
   with `P249-LREQ-CLRWAIT-TO`.
9. **`mxfs_dlm_caw_force_release_self` now takes a window too** — it is the most
   destructive clear in the file (every bitmap, every matching slot, no plan)
   and its caller's serialization is XFS-layer only, which says nothing about
   other local CAW attempts.
10. New ctx counters in `dlm/dlm_caw.h`: `lreq_clr_refuse`, `lreq_rel_kept`,
    `lreq_clrwait_ok`, `lreq_clrwait_to`. New constants
    `MXFS_CAW_LREQ_CLRWAIT_MS` / `_STEP_MS`.

## What is OWED — the publication half (this is why it is still unsafe)

`lreq_clr_snap` / `lreq_clr_still_good` are written but **called from nowhere**.
Until they are wired, memory-only grants can still publish straight through a
clear. Exact sites (line numbers as of srcversion `3C6F0BF…`, re-grep before
editing — they have moved twice already):

- **Already-held shortcut, exact mode** — snap after the `our_mode =
  node_held_mode(cur_slot, ctx->node_bit)` derivation; validate immediately
  before `rc = 0; /* Already hold it */ goto out;`. On failure `continue`.
- **Already-held shortcut, higher mode subsumes** — same, before
  `rc = 0; /* Current mode is sufficient */ goto out;`.
- **Direct-handoff adopt arm** in `caw_wait_for_grant` — snap after the
  `read_slot(ctx, slot_idx, cur_slot)` in the wait loop that produced the image
  being adopted; validate before its `rc = 0; goto out;`. This is the one with
  NO existing defence at all (it calls plain `caw_grant_meta_store`, not the
  `_unless_releasing` variant), so it is the biggest hole of the three.
- Bump `ctx->lreq_clr_refuse` on each refusal and log it (probe id not yet
  allocated — `P250-LREQ-CLR-REFUSE` is free).

Side effects already taken before the validation point (`caw_grant_meta_store`,
`caw_grant_seq_prebump`, `track_held`) are harmless on retry: a seq bump only
makes a concurrent unlock abort, which errs toward leaving the bit set.

## Also still owed (unchanged)

- The new defect is **NOT yet in `tests/criteria/OPEN_DEFECTS.json`** — file it
  (own entry, or as a second instance under D-SAMENODE-WAITER-CANCEL-COLLISION).
- **RULE-5 consult on this landing** before any rig cycle. Two judgement calls
  in it that were mine, not the ruling's, and should be put to GPT explicitly:
  (a) the blocker-6 wait is BOUNDED + fail-forward rather than unbounded, on
  RULE-0 grounds — note that an orphaned owed record does NOT leak forever,
  because `lreq_gc` keeps the entry alive and the next attempt on the resource
  collects it; (b) `caw_drop_own_waiter` re-derives the plan per iteration
  rather than holding a single plan.
- sess115 ruling leftovers: ICLUSTER quiescence (XFS-layer, not reachable from
  `dlm_caw.c`), the three admission-path audits, blockers 4/5/8/9/10, and the
  `tenure[]` naming/doc fix.
- Closure test (RULE 6) is still the sess113 debugfs exerciser with its negative
  control. A green board cannot close this.

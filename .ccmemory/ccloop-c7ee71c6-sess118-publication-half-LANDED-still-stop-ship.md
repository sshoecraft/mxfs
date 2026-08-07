---
name: ccloop-c7ee71c6-sess118-publication-half-LANDED-still-stop-ship
description: sess118: the clear-window PUBLICATION half is wired (3 arms) + ruling items 4/6 landed. srcversion AC44AC4… Still STOP-SHIP — 6 of 8 blockers open.
metadata:
  type: reference
tags: [mxfs, dlm-caw, lreq-registry, sess118, partial-landing, do-not-deploy]
---

# sess118 — publication half wired; 6 of 8 ruling blockers still open

**VERSION still `0.11.441` (deliberately not revved — landing incomplete).
srcversion `3C6F0BF4547E9A22C95A0ED` → `AC44AC4FAF6EF5DA0C24299`. Builds clean,
zero warnings (the two "defined but not used" are gone — that WAS the unwired
half). STILL STOP-SHIP. Fleet stays on 0.11.440.**

Ruling this must satisfy: `…sess118-GPT-ruling-clear-window-8-blockers`.

## Landed this session (all `dlm/dlm_caw.c`)

1. **`lreq_clr_snap` / `lreq_clr_still_good` are WIRED** at the three
   memory-only publication arms. Each refusal bumps `ctx->lreq_clr_refuse`,
   logs `P250-LREQ-CLR-REFUSE arm=held|held-hi|adopt`, sleeps 1ms, `continue`s.
   - already-held shortcut, exact mode — after the relwait gate, before
     `caw_grant_result_fill` / `rc = 0`.
   - already-held shortcut, higher-mode-subsumes — same position.
   - **direct-handoff ADOPT arm** in `caw_wait_for_grant` — placed as an
     `else if` BEFORE the `else` block, so it validates ahead of EVERY side
     effect (`caw_grant_result_fill`, `caw_grant_seq_prebump`, `track_held`,
     `caw_grant_meta_store`). This arm had no prior defence of any kind.
2. **Snapshot ordering CORRECTED and CONFIRMED by the ruling.** Snap is armed
   BEFORE the read it protects, not after: `csnap` right before `find_slot_skip`
   at the top of every acquire retry iteration; `wsnap` right before the wait
   loop's `read_slot`. The sess116 design note said "after the read" and was
   wrong — the argument is written into the comment above `lreq_clr_snap`.
3. **Ruling item 4 (registry ABA)**: `lreq_clr_still_good` now FAILS CLOSED on a
   missing entry (`ok = e && …`, was `ok = !e || …`).
4. **Ruling item 6 (tenure wrap)**: `lreq_finish` saturates `tenure[held_mode]`
   at `UINT32_MAX` instead of wrapping. Nothing decrements it in the
   cached-grant model, so a shortcut-heavy workload could have wrapped it to
   zero and read as "no local tenure" — authorising the exact clear the guard
   exists to refuse.

## OWED — the 6 remaining ruling blockers, hardest first

- **#1 post-validation demotion race** — the residual window between validation
  and the caller's USE of the grant. My "out of scope for dlm_caw.c" conclusion
  was REJECTED. Three acceptable dispositions only (XFS quiescence / DLM
  active-user reference with `use_end` / prove every unlock+force-release caller
  already quiesced). This is the largest item and is shared with the sess115
  ICLUSTER-quiescence blocker.
- **#2 fail-forward owed cleanup** — the 50ms bounded wait in `lreq_finish` is
  NOT acceptable ("there may be no next attempt from this mount"). Preferred
  restructure: **record the owed intent under the registry mutex BEFORE the long
  disk-I/O portion of the clear**, so `lreq_finish` synchronises only with the
  short intent-publication phase; plus a pinned per-resource worker with
  guaranteed progress that does not require re-acquiring the resource.
- **#3 ambiguous CAW result** — `committed` passed to `lreq_clr_end` must mean
  MAY-have-changed-the-slot. Audit all three windows: only a definite
  compare-miscompare/no-write may pass `false`; an I/O timeout or transport
  error must pass `true`.
- **#5 allocation failure** — `lreq_clr_begin` returning NULL must fail closed
  everywhere. `caw_drop_own_waiter` already refuses; **`mxfs_dlm_caw_unlock_gen`
  currently PROCEEDS** under the legacy mark. Needs a reserve/mempool so the
  destructive path can never be unregistered.
- **#7 force-release precondition** — `mxfs_dlm_caw_force_release_self` must
  prove it runs only after dependent activity stopped (or in a terminal fenced
  state).
- **#8 multi-step clears** — per-iteration `lreq_plan` re-derivation is RIGHT
  (ruling Q3b) but `lreq_plan` records owed state as a side effect on every
  derivation, and a later successful CAS does not retract the owed flags an
  earlier iteration set. Audit: a satisfied owed flag must be cleared by the CAS
  that satisfies it.
- Plus ruling (iii): audit that every retry path shares ONE absolute deadline
  (no nested loop with its own).

## Also still owed

- The ledger entry `D-SAMENODE-WAITER-CANCEL-COLLISION` has NOT been updated
  with the sess117/118 landing or this ruling — `next_step` still ends at the
  sess115 ruling.
- Closure test (RULE 6) is still the sess113 debugfs exerciser + negative
  control. A green board cannot close this.

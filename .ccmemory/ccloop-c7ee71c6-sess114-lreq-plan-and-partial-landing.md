---
name: ccloop-c7ee71c6-sess114-lreq-plan-and-partial-landing
description: sess114: 3 of the 10 sess114 blockers landed (builds clean, still STOP-SHIP core); plus the effective-mode reduction that collapses blockers 2+3.
metadata:
  type: reference
tags: [mxfs, dlm-caw, lreq-registry, sess114, implementation-plan]
---

# sess114 — partial landing + the reduction that makes blockers 2/3 tractable

Ruling: `…sess114-GPT-ruling-cancelling-accepted-10-more-blockers`.

## Tree state

VERSION still **0.11.441** (deliberately NOT revved — the STOP-SHIP core is
still in the tree and must not board). srcversion moved
`750BDB5F2A229A3B8438947` → **`B385712E9A1F9A025F1D3C1`**. Builds clean.
Fleet still on 0.11.440. **DO NOT DEPLOY.**

## What landed this session (3 items, all independent of the disputed core)

1. **Both `waiters_ex` setter sites** (`dlm_caw.c` acquire ~5288, convert ~6912)
   now use `mxfs_mode_can_write(mode)` instead of an open-coded `EX||PW`, and
   set `waiter_mode = recompute_waiter_mode(new_slot)` instead of the monotone
   raise `if (mode > waiter_mode) waiter_mode = mode`. Setter and recompute are
   now literally the same function, so they cannot disagree about the field's
   meaning. GPT confirmed safe given FACT 5; behavioural delta is PW-waiter →
   `waiter_mode=EX`, and the sole consumer (`defer_for_waiter`) already treats
   EX and PW identically.
2. **Registry allocation failure now FAILS the DLM context create** (ruling
   item 10) with a full unwind of everything allocated before it. Note
   `orphan_clock_lock` is a **spinlock**, not a mutex — `mxfs_pal_mutex_destroy`
   on it is a compile error (-Werror=incompatible-pointer-types).
3. **`ctx->lreq_cond`** added (`dlm_caw.h` next to `lreq_lock`, created in ctx
   create, destroyed in ctx destroy). Nothing waits on it yet — it is the
   parking spot for the `op` protocol below.

## The reduction: `refs` collapses blockers 2 and 3

GPT's blockers 2 (structurally enforce final-local-reference unlock) and 3
(node-wide effective mode through conversion/downgrade/release) are one
mechanism, and it needs NO on-disk change:

> **The node's disk holder state may only be WEAKENED when no remaining local
> reference requires the stronger mode.** A stronger-than-needed hold is always
> safe (superset); only weakening can uncover a live local reference.

- Add an aggregate `refs` count alongside `tenure[]` (both bumped in
  `lreq_finish`'s one critical section).
- **Unlock** (mode-less, clears every node bit): under the entry's exclusive
  op, if `refs > 1` → **do not issue the disk clear at all**; just drop the
  reference. The surviving reference keeps the existing (≥ its demand) hold.
  Only `refs == 1` clears and zeroes tenure. This is exactly GPT's "assert and
  enforce that the aggregate local reference count is the final releasable
  reference; if it is not final, do not issue the disk clear" — and it sidesteps
  the mode-less-API problem entirely, because the guard needs no mode.
- **Convert to a weaker mode**: apply the registry move under op, recompute
  `effective = max{m : tenure[m] > 0}`; if `effective > new_mode` the disk write
  is a **no-op** (node already holds ≥ effective ≥ new_mode). Otherwise do the
  disk downgrade. Covers GPT's A-converts-PR→EX-while-B-holds-PR example and the
  two-local-EX downgrade hole.
- Stale-high `tenure[m]` after a non-final unlock is **fail-closed** for the
  cancel guard (it refuses to clear) — a liveness leak collected by debt, never
  a corruption.

## Blocker 1 (RELEASING) has a second half I have NOT yet solved

Blocking `lreq_join` during RELEASING does **not** close GPT's sequence,
because the publisher can be an **already-joined** attempt: B is parked in
`caw_wait_for_grant`, a BAST drives U into unlock, B is granted mid-unlock and
publishes. Two consequences:

- `lreq_release_all` must subtract a **snapshot taken under op before the CAS**,
  not blanket-`memset` the tenure vector, or it eats B's fresh tenure.
- Worse and independent of the registry: U's unlock CAS clears our node bit in
  **every** bitmap, so on a miscompare-retry it would clear B's fresh grant bit
  on disk. `dlm_caw.c:~5640` documents this exact shape as PROVEN
  (P135-INO-UNLOCK → P106-EXGRANT → strip hex=1→0 → P108) and there is a guard
  at ~5647 (`node_held_mode == NL && !waiters && !yield_to` → treat as already
  released). **NEXT SESSION: read the whole unlock retry loop and establish
  whether that guard actually covers the grant-lands-mid-unlock case, or whether
  the `refs`/op protocol has to cover it.** Do not assume it does.

## Remaining blockers, in the order I would take them

blocker 2+3 (the `refs` reduction above) → blocker 1 (RELEASING op + snapshot
subtraction + the unlock-retry question) → blockers 6+7 (finish-vs-CANCELLING
wait-before-decrement protocol; holder test over **all** modes in `holder_mask`
and `others == 0` for every waiter clear) → the CANCELLING op itself →
blockers 4+5+8 (debt: never drop a record, real claim cookie, wall-clock
deadlines) → blocker 9 (post-upgrade old-bit residue as tracked debt) →
blocker 10 (withdrawal fences local I/O first) → item 9 checked arithmetic +
`_Static_assert(MXFS_LOCK_MODE_COUNT <= 32)` + CR/CW rejection at the transport
boundary so FACT 5 cannot silently lapse.

Closure test (RULE 6) is still the sess113 debugfs exerciser with its negative
control — a green board cannot close this (sess111 measured the reconcile arm
entered 0 times on all 32 nodes).

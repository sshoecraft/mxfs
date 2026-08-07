---
name: ccloop-c7ee71c6-sess120-blocker5-and-3-windows-LANDED
description: sess120: ruling item 5 (ENOMEM fail-closed) LANDED via an allocation-free clear window + entry reserve, and all 3 audit sites windowed. srcversion C3…
metadata:
  type: reference
tags: [mxfs, dlm-caw, lreq-registry, sess120, samenode-waiter, stop-ship, clear-window, fail-closed]
---

# sess120 — blocker 5 landed, and the three unwindowed clears are windowed

Build: VERSION still `0.11.441` (landing still incomplete, not revved).
srcversion `A78D555EAA0734BC6BBFD6E` → `C3127EAA4E9A2D59061A79D`. Builds clean,
zero new warnings (the one `mxfs_dlm_lkt_dump` missing-prototype warning in
`dlm.c` is pre-existing and unrelated). STILL STOP-SHIP — fleet on 0.11.440.

Continued D-SAMENODE-WAITER-CANCEL-COLLISION (ledger #16) rather than starting
at #1, for the same reason as sess119: the tree is mid-landing under the
sess118 stop-ship ruling.

## Blocker 5 — "an ENOMEM fallback that proceeds without registry coverage is a
## correctness defect"

The fix is not a fallback policy, it is removing the allocator from the
destructive path. Three pieces:

**1. `lreq_clr_begin` is now FIND-FIRST and allocation-free.** It used to
allocate a spare entry BEFORE looking, then free it if it lost the race — so
every destructive clear called `mxfs_pal_alloc` even though the entry almost
always already exists. It does exist: `lreq_finish` publishes `tenure[]` and
`lreq_gc` refuses to free an entry with nonzero tenure, so any resource this
node holds a grant on already has one. Unlock and both DIVERG arms therefore
never allocate at all.

**2. A per-ctx reserve (`ctx->lreq_reserve`, 64 entries, `MXFS_CAW_LREQ_RESERVE`)
covers the genuinely-absent case.** `lreq_reserve_take`/`_give`/`_fill`.
Restocked ONLY from allocation-safe contexts: mount, and `lreq_join`'s existing
outside-the-lock allocation (the loser of a join race is donated to the reserve
instead of freed, plus a top-up call). `lreq_gc` now returns quiescent entries
to the reserve rather than freeing them, which makes the steady state
self-sustaining — an entry a clear window creates goes straight back when that
window closes, so the steady-state draw is zero.

**The second, independent reason this had to change:** `mxfs_pal_alloc` is
`GFP_KERNEL` (pal/linux/kern.c:1600). Reclaim entered from inside a DLM release
can re-enter XFS writeback, which acquires the very DLM resource being
released. That is the ruling's "allocation must not happen with a lock held
whose reclaim path re-enters MXFS/DLM", and it was live on the unlock path.

**3. Every destructive site now fails CLOSED.** New tri-state return:
`MXFS_CAW_CLR_ARMED` / `MXFS_CAW_CLR_NOREG` (no registry — unchanged legacy
behaviour) / `-ENOMEM`. Plus `lreq_clr_begin_wait`, a bounded wait for the
reserve to be restocked by a concurrent window closing (20ms default, clamped
to the CALLER'S EXISTING deadline when it has one, so it can never extend a
lock budget; `!ctx->running` escape for ruling item (iii) shutdown
compatibility).

Dispositions:
- `caw_drop_own_waiter` — refuse and OWE. Already correct in sess119; only the
  signature and probe name changed.
- **`mxfs_dlm_caw_unlock_gen` — the one that actually changed behaviour.** It
  used to "proceed under the legacy mark alone", with a comment arguing that
  stranding the lock is worse than the residual aliasing hole. That trade is not
  available and the two outcomes are not comparable: a stranded lock is a stall
  that resolves when the peer re-BASTs, an unlinearized clear strips a bit a
  local writer is still using. Now returns `-EIO` with the lock held, after
  undoing `caw_release_mark`. Required moving the `unlock_deadline` derivation
  ABOVE the window open so the wait shares it.
- `mxfs_dlm_caw_force_release_self` — was the worst offender ("proceeding
  unlinearized" on the path that strips our bit from EVERY bitmap in EVERY
  matching slot). Now `-EAGAIN`.

New counter `ctx->lreq_reserve_dry` + probe `P251-LREQ-DRY`, reported at
teardown if nonzero.

## Ruling item (i) — the three audit sites are now windowed

New helper `caw_slot_clearing(ctx, resource, slot_idx, cur, new, site)` wraps
ONE destructive CAS in a window; fail-closed return is `-EAGAIN`, which all
three callers ALREADY route into their own bounded retry loop, so no caller
needed new control flow. Wired at:
1. `mxfs_dlm_caw_lock` DIVERG exact-mode arm — `"diverg-lo"`.
2. `mxfs_dlm_caw_lock` DIVERG higher-mode arm — `"diverg-hi"`.
3. `mxfs_dlm_caw_convert` DOWNGRADE arm — `"convert-downgrade"`. The
   consequential one: the CAS sets the new LOWER bit but strips the old HIGHER
   one, so `node_held_mode` (highest bit set) goes DOWN and a local thread
   holding `tenure[old_mode]` loses its on-disk authority. The subsumption
   argument that exempts the grant paths runs the OTHER way here.

**Why the window only spans the CAS, not the read that produced `cur`:** what a
publication validates is that no clear ran at its snapshot, none runs at its
validation, and none COMMITTED in between. A window opened at any point before
the destructive CAS and closed after it satisfies all three for any publication
whose snapshot→validate interval overlaps the CAS. Opening it back at the
acquire loop's slot read would make an ordinary retrying acquire look like a
clear in progress and bounce every concurrent publication on the resource.

## Remaining checklist items

- **Blocker 2** — the 50ms fail-forward wait in `lreq_finish`. GPT's preferred
  restructure: have the clearer record its cleanup intent/owed state under the
  registry mutex BEFORE entering the long disk-I/O portion, so `lreq_finish`
  synchronizes only with the short intent-publication phase and the orphan case
  disappears. Note `lreq_plan` already records owed state under the mutex — the
  restructure may be close to reachable by moving the plan derivation earlier.
- **Blocker 7** — explicit precondition on `force_release_self`.
- **Blocker 1** — the residual post-validation demotion window (XFS-layer
  quiescence, or a `use_begin`/`use_end` active-user reference in the DLM API).
  Largest, and the ruling refuses to let it out of scope.
- Ruling item Q3(b)'s audit note is still open: `lreq_plan` records owed state
  as a side effect on EVERY derivation, and a later successful CAS does not
  retract flags an earlier iteration set (monotone OR-ing).

Items 4 and 6 landed sess118; 3 and 8 sess119; 5 and (i) here. 1, 2, 7 open.

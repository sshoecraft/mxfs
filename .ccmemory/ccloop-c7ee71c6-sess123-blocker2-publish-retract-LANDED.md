---
name: ccloop-c7ee71c6-sess123-blocker2-publish-retract-LANDED
description: sess123: blocker 2's publish/retract state machine LANDED in dlm_caw.c (srcversion 2C6F2B2…, builds clean). The WORKER is the remaining half. Still S…
metadata:
  type: reference
tags: [mxfs, dlm-caw, lreq-registry, sess123, blocker2, owed-worker, stop-ship]
---

# sess123 — blocker 2: publish-first + proof-based retraction LANDED

Build: VERSION `0.11.441`. srcversion `1D16B8E6FA1DD5BDF32BD17` → **`2C6F2B264DAA72AFF5A05B0`**.
`make modules` exits 0; no `error:`, no source warnings (only the pre-existing
"compiler differs" + NFS clock-skew noise). **STILL STOP-SHIP — fleet stays on
0.11.440.** Not deployed, not rig-verified.

## What landed in `dlm/dlm_caw.c`

1. **Entry owed record reshaped.** `owed_slot` → `owed_slot_hint` (DIAGNOSTIC
   ONLY, never selects the slot written); added `owed_busy`, `owed_gen`,
   `owed_next_ms`. Long comment records why the target is the RESOURCE.
2. **`struct mxfs_caw_clear_plan` gained `holder_moot`** — set when the holder
   refusal was `tenure[giveup_mode] != 0`.
3. **`struct mxfs_caw_owed_intent`** — `{holder_mask, waiters, waiters_ex,
   slot_hint}`.
4. **`lreq_owed_pending()`** + **`lreq_owed_merge()`** (publish/merge; bumps
   `owed_gen` UNCONDITIONALLY — it is a retraction token, not a change counter;
   zeroes the backoff floor; counts `lreq_owed_pub` only on a real add).
   `lreq_gc` now uses `lreq_owed_pending` and also refuses on `owed_busy`.
5. **`lreq_plan` IS NOW PURE** (ruling item 2). Signature dropped `slot_idx`;
   all five `e->owed_* = ...` writes deleted; sets `holder_moot`.
6. **`lreq_owed_retract()`** — gen-guarded (`owed_gen != gen0` ⇒
   `lreq_owed_genrace++`, refuse), discharges the plan's PERMITTED set on proof,
   the whole record on `terminal`, and the moot holder bit unconditionally.
   Zeroes `owed_fails`/`owed_next_ms` and counts `lreq_owed_done` when the
   record empties.
7. **`caw_drop_own_waiter` converted to publish-first.** Publishes the MAXIMAL
   intent (`w`, `wx`, `h` if `giveup_mode != NL`) under `lreq_lock` and
   snapshots `gen0` BEFORE any I/O; broadcasts `lreq_cond`. The two old
   "requeue as owed" blocks are GONE (superseded — publication up front also
   covers the exits that never reached them). Window-open failure now returns
   **-EAGAIN** (was -ENOMEM). Proof tracking: `proven` on CAS rc==0 and on the
   no-permitted-bit-set image; `terminal` on tombstone magic and on resource
   memcmp mismatch. Retraction runs before `lreq_clr_end`.

## The remaining half — the WORKER (next session's first job)

Everything in ccmemory `ccloop-c7ee71c6-sess122-blocker2-design-and-header-landed`
under "The worker", "lreq_finish", "Teardown", "the 2 divergence sites" is still
UNWRITTEN. Concretely:

- `caw_owed_resolve()` — canonical `find_slot`; **`-ENOENT` is the terminal
  proof** (chain-exhausted). A read error is NOT (find_slot also returns raw
  read rc).
- `caw_owed_sweep()` / `caw_owed_dispatch()` / `caw_owed_worker_fn()` — claim
  under lock with `!owed_busy && !clr_active && pending && now >= owed_next_ms`,
  set `owed_busy` + `pin++` BEFORE unlocking (ruling item C), `_DISPATCH_MAX`
  per sweep, park on `lreq_cond` for `_BUSY_MS`/`_IDLE_MS`, exponential
  `owed_next_ms` (`_BACKOFF_MS << min(fails,7)` clamped to `_BACKOFF_MAX_MS`),
  P253-OWED-STUCK past `_ESCALATE`. **Do not touch `e` after `lreq_gc`.**
- Give `caw_drop_own_waiter` an `intent` param (NULL ⇒ maximal, as now) so the
  worker publishes exactly what is owed instead of re-inflating the record.
- Move publication INTO `lreq_clr_begin` (intent + `gen0` out-param, atomic with
  the window). Only remaining delta vs. what landed: coverage when the caller's
  `e == NULL` but the registry has/creates an entry. Also plan against `clr`
  when `e == NULL` (strictly safer than today's legacy clear-everything).
  `lreq_clr_begin_wait` call sites: 4 (`caw_slot_clearing`,
  `caw_drop_own_waiter`, unlock, release).
- `lreq_finish`: delete the CLRWAIT park (lines ~3541-3559) and the inline owed
  run (~3587-3624) — the latter is the sess116 `e=NULL` corruption path. Then
  delete `MXFS_CAW_LREQ_CLRWAIT_*` and `lreq_clrwait_ok/_to` from the header
  (marked for deletion there since sess122).
- Start/stop: create `ctx->owed_worker` in `mxfs_dlm_caw_start` when
  `ctx->lreq` — **fail the start** if it will not start (a missing collector is
  the measured 16-node wedge), joining `bast_poll_thread` on that error path.
  `mxfs_dlm_caw_stop` broadcasts `lreq_cond` then joins. Final drain sweep
  bounded by `_DRAIN_MS`, residue as P254-OWED-TEARDOWN (`lreq_owed_left`).
- `caw_slot_clearing` gains an intent; divergence sites 1+2 (`diverg-lo` at
  ~5320, `diverg-hi` at ~5484) pass `{h: our_mode}`; site 3 (convert-downgrade,
  ~7811) passes NONE.

## Method notes

- `make modules 2>&1 | grep | head` MASKS hard failures — redirect to a file,
  check `$?`, then grep.
- `find_slot` returns 0 / -ENOENT / raw read error. Only -ENOENT is proof.

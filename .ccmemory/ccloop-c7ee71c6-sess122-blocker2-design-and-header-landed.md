---
name: ccloop-c7ee71c6-sess122-blocker2-design-and-header-landed
description: sess122: blocker 2's full implementation design (all 8 ruling items resolved to concrete code) + the header half LANDED and building. The .c half is…
metadata:
  type: reference
tags: [mxfs, dlm-caw, lreq-registry, sess122, blocker2, owed-worker, stop-ship]
---

# sess122 — blocker 2: design settled, header landed, `.c` half is the next step

Build: VERSION still `0.11.441`. srcversion `AC4899E877E72D996AEF7B0` →
`1D16B8E6FA1DD5BDF32BD17`. `make modules` exits 0, no errors, no new warnings.
STILL STOP-SHIP — fleet stays on 0.11.440.

## What landed (dlm_caw.h only — additive, nothing uses it yet)

- `ctx->owed_worker` (mxfs_thread_t) + 7 counters: `lreq_owed_pub/_done/_moot/
  _genrace/_disp/_stuck/_left`.
- `lreq_cond` re-documented as the OWED-CLEANUP WAKE CHANNEL.
- Worker constants: `MXFS_CAW_OWED_TRIES 16`, `_DISPATCH_MAX 16`, `_IDLE_MS
  1000`, `_BUSY_MS 20`, `_BACKOFF_MS 4`, `_BACKOFF_MAX_MS 500`, `_ESCALATE 32`,
  `_DRAIN_MS 2000`, `_DRAIN_STEP_MS 20`.
- `MXFS_CAW_LREQ_CLRWAIT_*` and `lreq_clrwait_ok/_to` were deleted and then
  RESTORED, because `lreq_finish` still references them and the tree must build
  at the relay boundary. They are marked for deletion by the `.c` half.

## THE DESIGN — resolves all 8 ruling items to concrete code

The load-bearing simplification: **the obligation's target is the RESOURCE, and
the slot is derived, not stored.** That kills ruling item 6 (the overwriteable
`owed_slot`) outright — a location that is re-resolved every pass cannot be
overwritten — and it is the ruling's own accepted design (1). One owed record
per entry then suffices; no multi-target array is needed.

### Entry fields (replace `owed_slot`, keep the rest)

    uint32_t owed_holder_mask; bool owed_waiters; bool owed_waiters_ex;
    bool     owed_busy;      /* worker owns it right now */
    uint64_t owed_gen;       /* bumped by EVERY publish/merge */
    uint32_t owed_slot_hint; /* last known location — a HINT only */
    uint32_t owed_fails;
    uint64_t owed_next_ms;   /* backoff floor */

### `lreq_plan` goes PURE (item 2)

Delete all five `e->owed_* = ...` writes. It only READS attempts/writers/tenure.
Add `bool holder_moot` to `struct mxfs_caw_clear_plan`, set when the holder
refusal was because `tenure[giveup_mode] != 0`.

### Publication is INTENT-FIRST and atomic with the window (item 1)

`lreq_clr_begin(_wait)` gains an intent arg (`{w, wx, hmask, slot_hint}`, NULL
allowed) and a `gen0` out-param. Under ONE `lreq_lock` section it merges the
intent, bumps `owed_gen`, zeroes `owed_next_ms`, claims `clr_active++`, takes
`pin++`, snapshots `pub_seq`. Callers broadcast `lreq_cond` after unlocking.

`caw_drop_own_waiter` publishes the MAXIMAL intent up front —
`{w:true, wx:true, h:(giveup_mode != NL)}` — then retracts what it proves.
On a window that cannot open it publishes the intent anyway and returns
**-EAGAIN** (was -ENOMEM), because the record now guarantees a retry.

### Retraction: gen-guarded, plan-guarded (items 4 + 5)

    discharge = the plan's PERMITTED set, and only when there is proof every
                permitted bit is now clear.

Proof comes from exactly three places: (a) a CAS that landed after clearing
every permitted-and-set bit; (b) an image in which no permitted bit was set;
(c) **the resource has no live slot at all** — that is the terminal transition
ruling item D demands, and canonical resolution is what makes it reachable.
Retraction runs under `lreq_lock` and is refused if `owed_gen != gen0`
(`lreq_owed_genrace++`) — that is the A-erases-B's-newer-intent race.

Bits the plan REFUSED are never discharged (item 5 explicit) — WITH ONE
EXCEPTION that is itself required for termination: a holder refusal with
`holder_moot` (a live local tenure owns the bit) discharges, because the bit is
authorized, not dirt, and its owner's unlock clears it. Without this the worker
would spin forever on a bit that can never become clearable.
Waiter refusals (`others != 0`) stay owed and terminate naturally when
attempts reaches 0.

### ABA / at-most-one-live-slot (ruling item B, design-(1) conditions)

Canonical resolution makes identity a non-issue: what AUTHORIZES the clear is
the plan evaluated at CAS time (no live local attempt, no live local tenure ⇒
any of our bits on this resource are stale by definition), not the slot's
incarnation. A tombstone→recreate of the same resource can only carry our bit
if a NEW local attempt set it, and that attempt is exactly what makes the plan
refuse. `memcmp(resource)` stays as the different-resource guard.

### The worker (items 3 + 7 + C + F)

`caw_owed_worker_fn` — its own kthread, NOT the BAST poll thread.
Sweep: walk buckets from a rotating start; claim an entry only when
`!owed_busy && clr_active == 0 && now >= owed_next_ms && pending` (item 3);
set `owed_busy` + `pin++` BEFORE dropping the lock (item C — the pin must cover
the whole unlocked use, because the worker can retract the last owed flag while
still holding the raw pointer); at most `_DISPATCH_MAX` entries per sweep
(item F); at most `_TRIES` CAS per dispatch; re-lock to unpin, bump
`owed_fails`, set exponential `owed_next_ms`, and GC.
Park on `lreq_cond` for `_BUSY_MS` / `_IDLE_MS` (immediate wakeup + periodic
missed-wakeup net). Past `_ESCALATE` failures: P253-OWED-STUCK, keep retrying.

### `lreq_finish` (items 3 + A)

Delete the CLRWAIT park and the inline owed run entirely — intent-first
publication removes the orphan race the park existed for, and the inline run is
the path that caused the sess116 `e=NULL` corruption. It becomes: publish
tenure, drop attempts, and if owed work remains do NOT gc — just broadcast.

### Teardown (item 8)

`mxfs_dlm_caw_stop` sets `running=false`, broadcasts, joins the worker. The
worker, after its main loop, runs a FINAL drain sweep (ignoring backoff floors)
bounded by `_DRAIN_MS`; residue is reported as P254-OWED-TEARDOWN with a count,
and membership withdrawal at unmount is what makes those bits reclaimable by
peers. Stop() runs before `mxfs_dlm_caw_release_all` in destroy, so the ctx is
still fully functional during the drain.

### Also in scope: the 2 divergence `caw_slot_clearing` sites

Sites 1+2 (`diverg-lo` / `diverg-hi`) strip a provably-stale holder bit for
`our_mode`; if that CAS never lands, nothing else collects it (the give-up path
uses the REQUESTED mode, not `our_mode`). They get an intent `{h: our_mode}` and
retract on rc==0. Site 3 (`convert-downgrade`) gets NONE — an abandoned
downgrade leaves the higher mode held, which is the safe direction.

## Method note (carried from sess121, cost a session there)

`make modules 2>&1 | grep ... | head -20` MASKS hard build failures. Always
redirect to a file, check `$?`, then grep the file.

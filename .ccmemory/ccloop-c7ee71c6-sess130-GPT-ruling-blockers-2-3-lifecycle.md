---
name: ccloop-c7ee71c6-sess130-GPT-ruling-blockers-2-3-lifecycle
description: sess130 RULE-5 ruling on the blockers 2+3 lifecycle design: my proposed order was WRONG (release_all before quiescence is a race). Corrected plan + w…
metadata:
  type: reference
tags: [mxfs, dlm-caw, sess130, gpt-ruling, blocker2, blocker3, lifecycle, stop-ship, teardown]
---

# sess130 — GPT ruling on blockers 2+3, and the partial landing

Tree `0.11.445` → **0.11.446**, srcversion `9A4FD08BE505182F28316CD`, builds
clean. Fleet still on 0.11.440. **STILL STOP-SHIP** — blockers 2 and 3 are
PARTIALLY landed (state + episode clock only; the lifecycle restructure is not
written yet).

Continued D-SAMENODE-WAITER-CANCEL-COLLISION (ledger #16), same reason as
sess119–129.

## THE RULING — my design was wrong in a way I would not have caught

I proposed: gate admission at `lreq_join`, wait for in-flight → 0, keep
`release_all` where it is (BEFORE the drain), then drain. GPT found the race
that makes the ordering mandatory, and it is a REAL one that exists in the
code today:

```
release_all clears every holder bit
   an acquire ALREADY INSIDE the door continues
   it succeeds and re-takes a holder bit
   it publishes NOTHING — success needs no cleanup
quiesce observes that operation finish
drain finds no obligation
node sends GOODBYE while still holding the bit on disk
```

**`release_all` must run AFTER the gate closes and the in-flight count hits
zero, in an exclusive phase.** Required order:

```
close acquisition admission
wait for all already-entered acquire/convert
stop/join any other publication-capable producer
run release_all EXCLUSIVELY
publish every release_all failure
drain obligations under the absolute deadline
IFF all clear:  GOODBYE + clean release_slot
ELSE:           withdraw/fence, NO clean departure
```

### The other rulings, all of which change the design

1. **Publication must precede the global decrement, in the SAME `lreq_lock`
   critical section.** That is the entire proof; state it explicitly.
2. **A quiesce timeout must NOT permit teardown to continue.** Proceeding lets
   a late producer publish after the final zero test — it destroys the very
   claim. On timeout: mark failed, withdraw, no GOODBYE, no clean slot
   release, and KEEP the ctx/registry/transport alive. (My resolution: keep
   waiting for `ops_active == 0` rather than free under a live user — the wait
   is bounded in practice by `MXFS_CAW_WAIT_TIMEOUT_MS` = 120000, the longest
   per-op deadline, so the quiesce deadline must exceed 120s or escalation is
   routine, not exceptional.)
3. **GOODBYE + clean slot release belong ONLY on the clean-success branch.**
   A false clean departure authorises peers to reclaim without the
   fence/replay protocol that makes reclaim safe; the slow death-detection
   path is the lesser evil.
4. **TWO escalation triggers, not one.** Runtime age (`OWED_ESCALATE_MS`) AND
   shutdown-drain-deadline expiry with residue. The 2000ms DRAIN_MS and the
   5-minute age are different deadlines; drain expiry must escalate then and
   there. GPT also notes DRAIN_MS=2000 against PASS_MS=1000 admits ~2 entries,
   so a queue of any depth withdraws even when every op would have cleared.
5. **The callback must not be the safety latch.** Record failed / admission
   closed / clean-departure-forbidden SYNCHRONOUSLY under the lock, THEN
   invoke. If the callback is unregistered, racing, or its work cancelled, the
   recorded state must still prevent GOODBYE.
6. **Schedule-after-cancel is real** — but see the code fact below, which
   closes it for free.
7. **Diagnostic must carry the membership epoch** (mine omitted it) plus node
   /mount identity and WHICH trigger fired.
8. **Episode age has an attribution problem** — A ages, B merges, A retracts,
   entry never goes non-pending, B inherits A's age. Episode age is the
   conservative choice, but then the log line must say "this resource has had
   continuously outstanding cleanup for X", NOT "these bits are X old".
9. **Final residue check must scan authoritative registry state under
   `lreq_lock`**, not queue emptiness. (`caw_owed_count` already walks the
   buckets — correct as-is.)
10. Two distinct concepts: publication producers (the no-late-obligation
    proof) vs. ALL externally entered ops (ctx/registry/transport lifetime).

## CODE FACTS line-verified this session (keep these)

- **`lreq_join` has exactly 2 call sites, `lreq_finish` exactly 4**, and they
  are matched enter/leave pairs on exactly `mxfs_dlm_caw_lock` and
  `mxfs_dlm_caw_convert`. Both functions have a SINGLE `out:` label (7295,
  9041); every return before `lreq_join` is argument validation.
- **`caw_drop_own_waiter` has 5 call sites**, not 4: 4028+4045 are
  `caw_owed_dispatch` (collector, `collector=true`, publishes nothing —
  line 3505 `if (!collector)` builds the intent), 5542 is inside
  `caw_wait_for_grant` (whose only callers are 7170 in caw_lock and 8997 in
  caw_convert), 7291 caw_lock `out:`, 9037 caw_convert `out:`.
- **THE SCHEDULE-AFTER-CANCEL RACE CLOSES ITSELF.** `xfs_fs_put_super`
  (pal/linux/xfs_super.c) does `mp->m_mxfs_dlm = NULL` (1553) →
  `cancel_work_sync(&mp->m_mxfs_withdraw_work)` (1554) → `mxfs_v5_dlm_shutdown`
  (1566). `mxfs_dlm_shutdown_withdraw()` returns early on `!mp->m_mxfs_dlm`, so
  an escalation fired from inside the shutdown drain CANNOT re-arm the work.
  Shutdown-path escalation therefore relies purely on the DLM's own recorded
  state (which is the design GPT demanded anyway); runtime escalation on a live
  mount takes the full tested channel.
- **`mxfs_dlm_caw_destroy` calls `mxfs_dlm_caw_release_all` AFTER
  `mxfs_dlm_caw_stop`** (10416/10419) — i.e. after the worker is joined. Any
  obligation published there can never be collected. Second-order bug: in the
  `withdrawn` case `mxfs_v5_dlm_shutdown` deliberately SKIPS release_all (4054
  gate) but destroy's unconditional call runs anyway, defeating the D2 freeze.
  Delete destroy's release_all as part of this landing.
- `mxfs_dlm_caw_stop` has 5 callers (v5_mount 3754, 4111; dlm/mount.c 2508,
  2778; destroy 10416) — so DON'T change its signature; use a
  `set_release_on_stop(ctx, bool)` flag instead, set by v5 to `!withdrawn`.
- `MXFS_CAW_WAIT_TIMEOUT_MS = 120000`, `MXFS_CAW_UNLOCK_DEADLINE_MS = 5000`,
  `MXFS_CAW_MAX_RETRIES = 100`. These are what `OWED_ESCALATE_MS` and the
  quiesce deadline must be DERIVED from — GPT rejected "5 minutes" as
  arbitrary and rejected deriving it from the old 32-pass constant.
- Up-callback plumbing exists at both layers:
  `mxfs_dlm_caw_set_holders_alive_fn(ctx, fn, data)` (caw ← v5) and
  `mxfs_v5_dlm_set_*_notify(ctx, cb, data)` (v5 ← xfs). Architectural
  invariant 4 makes a callback mandatory — dlm/ must build user-mode.

## WHAT ACTUALLY LANDED on 0.11.446

State and the episode clock only — every edit is inert until the lifecycle
restructure wires it up, so 0.11.446 is behaviourally identical to 0.11.445.

- `dlm_caw.h`: `ops_closed` / `ops_active` / `ops_refused` (the admission
  gate), `departed_clean` (starts FALSE — fail-closed), `owed_failed` /
  `owed_failed_ms` / `owed_stuck_fn` / `owed_stuck_data`. The comment block
  carries the proof statement and the release_all race that forces the order.
- `dlm_caw.c` `struct mxfs_caw_lreq`: `owed_since_ms`, `owed_last_rc`.
- `lreq_owed_merge`: stamps `owed_since_ms` on the not-pending → pending edge
  ONLY (a merge extends the episode, never restarts it — that restart is how
  continuous publication would suppress escalation forever, ruling blocker 7's
  surviving half).
- `lreq_owed_retract`: clears `owed_since_ms`/`owed_last_rc` in the same block
  that already resets `owed_fails`/`owed_next_ms`.

## NEXT SESSION — the remaining steps, in order

1. `caw_op_enter/leave` helpers (increment/decrement `ops_active` under
   `lreq_lock`, refuse when `ops_closed`), applied to the WRITE SET:
   lock, convert, unlock, unlock_gen, force_release_self, open_set,
   open_clear, flush_held_to_disk, purge_node, purge_dead_nodes(_ex),
   grant_handoff. Pure readers stay ungated (documented, not overlooked).
2. `mxfs_dlm_caw_stop` restructure: quiesce → EXCLUSIVE release_all (gated by
   the new `release_on_stop` flag) → drain → authoritative residue check →
   set `departed_clean`. Delete destroy's post-stop release_all.
3. `mxfs_dlm_caw_release_all` publishes its 20-retry CAS failures (sess126's
   "separate gap, same family") — now collectable because it runs before the
   drain. GPT: an allocation failure that prevents publication must ESCALATE,
   not log-and-continue.
4. `mxfs_v5_dlm_shutdown`: drop its own release_all, call caw_stop EARLY
   (before GOODBYE, with lease/discovery/heartbeat still up), gate the GOODBYE
   broadcast and `mxfs_disklock_release_slot` on `!withdrawn && departed_clean`.
5. Blocker 3 proper: derive `OWED_ESCALATE_MS` from the deadline constants
   above, both triggers, the latch set atomically with `owed_failed` +
   `ops_closed` + `departed_clean = false`, the single actionable `pr_err`
   WITH membership epoch, and the `owed_stuck_fn` chain caw → v5 → xfs →
   `mxfs_dlm_shutdown_withdraw`. Clear `owed_stuck_fn` under `lreq_lock` after
   the worker join so no escalation can be issued post-join.

Closure for D-SAMENODE-WAITER-CANCEL-COLLISION still requires the sess113
debugfs exerciser — a green board CANNOT close it (sess111 measured the
reconcile arm entered 0 times on all 32 nodes).

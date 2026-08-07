---
name: ccloop-c7ee71c6-sess126-GPT-ruling-owed-worker-7-blockers
description: sess126 RULE-5 ruling on the sess125 owed worker: RELEASE BLOCKED, 7 blockers. -ENOENT/pin/gen arguments SURVIVE but must be restated narrowly.
metadata:
  type: reference
tags: [mxfs, dlm-caw, sess126, owed-worker, gpt-ruling, stop-ship, blocker2]
---

# sess126 — RULE-5 ruling on the sess125 owed-cleanup worker

Tree at 0.11.442 / srcversion `B2E4583BA40413F3B2704D2`, UNCHANGED this
session (no edits yet). Fleet still on 0.11.440. **STILL STOP-SHIP.**

Verdict: **"Do not deploy this collector to the 32-node rig yet."** The
obligation/pin/generation model is "fundamentally reasonable" and there is
**no use-after-free in the claim array** — but 7 release blockers.

## What I verified myself BEFORE the consult (all line-checked, keep these)

- `caw_tombstone_slot` (dlm_caw.c:1101) memsets and preserves ONLY
  {generation, resource, dir_epoch, last_ex_slot, ex_grant_epoch,
  open_holders}. So a tombstone **provably zeroes** `waiters`,
  `waiters_ex`, all `holders_*`. The sess122 terminal claim holds for
  tombstones.
- **No code path ever writes `magic = 0` over a used slot.** All three
  `memset(new_slot, 0, ...)` sites (5632, 7840, 10175) immediately set
  `magic = MXFS_CAW_MAGIC` as part of a claim CAS. The probe-chain
  invariant is intact.
- `find_slot` returns `-ENOENT` in TWO cases: probe terminated at a
  never-used slot, OR all 65536 scanned. Read errors return the errno,
  not -ENOENT — so `caw_owed_resolve` correctly treats them as
  non-terminal.
- `ctx->lreq` / `lreq_lock` / `lreq_cond` are allocated **all-or-nothing**
  (9680-9698), so the start-time worker condition cannot silently skip.
- `mxfs_dlm_caw_start` sets `running = true` BEFORE thread create. Fine.
- `caw_drop_own_waiter`'s 1000-attempt CAS loop **never checks
  `ctx->running`** — this is what breaks the drain bound.
- `mxfs_dlm_caw_release_all` does NOT use `caw_drop_own_waiter`; it has
  its own 20-retry CAS loop and publishes NO obligation. So it does not
  create post-worker-exit obligations — but its own failures leave bits
  with no record, no counter, no warning, at unmount. Separate gap,
  same family, worth filing.

## The 7 blockers, ranked (GPT)

1. **Teardown is neither bounded nor cancellation-aware.** CONFIRMS my A.
   `OWED_DRAIN_MS` is checked only BETWEEN sweeps; one drain sweep is
   16 entries x 4 modes x 1000 attempts x 8ms ≈ 512s, plus find_slot
   walks and I/O. Fix: propagate an ABSOLUTE DEADLINE through
   `sweep → dispatch → resolve → drop_own_waiter → find_slot`, checked
   before each claim, mode, slot read, CAW and retry sleep. Replace the
   1000-retry policy with an elapsed-time budget ("a retry count is not
   a time bound"). In drain, process ONE bounded op per deadline check —
   don't claim 16 with 2s left. Return `OWED_DONE/RETRY/DEADLINE/FATAL`.
   NOTE: if slot I/O itself can block past the deadline, we must not
   advertise DRAIN_MS as a hard bound at all.
2. **Shutdown ordering lets obligations be published after the collector
   exits.** This CONTRADICTS the sess125 "join owed worker FIRST"
   choice. `running=false` does not establish that producers quiesced.
   Required order: close admission → quiesce acquire/release producers →
   stop+join BAST/other PRODUCER threads → keep low-level LUN transport
   alive → drain collector under hard deadline → escalate if residue →
   stop collector → tear down transport+registry. If a BAST thread is
   both producer and transport, SPLIT those roles. The final zero-count
   test must happen after all publishers are quiesced.
3. **Escalation does nothing.** CONFIRMS my D, and it is a BLOCKER.
   P253 + counter at 32 passes changes no behaviour. Must be a
   WALL-CLOCK deadline (a pass can take minutes), and on expiry:
   mark the mount/DLM failed, reject new acquisitions, force
   shutdown from a context that cannot deadlock with `lreq_lock`,
   withdraw membership / run the fencing protocol (peers may only
   reclaim after withdrawal), keep state until they can, one actionable
   error with resource/bits/age/last-rc/membership epoch. **Do NOT fix
   this by blindly clearing holder bits.**
4. **Drain-mode bucket starvation.** `drain=true` ignores backoff, so
   every sweep re-claims the same first 16 eligible entries of a hot
   bucket; later entries may never be visited. Fix: a real owed-ready
   QUEUE (enqueue on the not-pending→pending transition, requeue at tail
   on release, delayed queue/timer heap for backoff); the hash table
   stays for LOOKUP, not scheduling.
5. **The collector republishes obligations it already owns.** CONFIRMS
   my B — and it is worse than cosmetic: every mode bumps `owed_gen`,
   which can make CONCURRENT USEFUL RETRACTIONS refuse. Fix: add
   `lreq_clr_begin_existing()` that takes `clr_active++`/`pin++` and
   snapshots `owed_gen` but does NOT call `lreq_owed_merge` and does NOT
   bump the gen. Also re-read the owed mask/waiter flags under the lock
   AFTER EACH MODE instead of iterating the top-of-dispatch snapshot.
   (Passing w/wx on the first mode only is NOT the final design.)
6. **Condvar lost-wakeup window.** All broadcasts are outside
   `lreq_lock` and the worker does an UNCONDITIONAL timed wait after
   reacquiring, so a publication landing in the gap waits up to
   IDLE_MS=1000ms. Fix: predicate under the mutex — `owed_work_seq`
   bumped under `lreq_lock` on every publication; loop
   `while (running && !owed_work_due_locked(...) && seq == ctx->owed_work_seq)`;
   timeout = earliest `owed_next_ms`, not a constant. Also make
   `running` READ_ONCE/WRITE_ONCE or atomic.
7. **Failure/backoff state not reset between obligation episodes.**
   *** LIKELY A FALSE POSITIVE — VERIFY FIRST. *** `lreq_owed_retract`
   (dlm_caw.c:2105-2109) already does
   `if (!lreq_owed_pending(e)) { owed_fails = 0; owed_next_ms = 0; }`
   on BOTH the terminal and the proven paths, and it runs before
   `caw_owed_release`. The SURVIVING part of the point is real though:
   define when an episode STARTS and track `owed_since_ms` separately
   from `owed_fails`, or continuous publication suppresses the
   wall-clock escalation of blocker 3 forever.

## Rulings on my four questions

1. **`-ENOENT` terminal?** The proof SURVIVES but must be RESTATED
   NARROWLY. A non-atomic 65536-slot walk is NOT a linearizable "the
   resource is absent now" — a concurrent claimant can create a live
   slot after the walker passed. What IS provable: *no stale bit from
   the old slot can survive a tombstone/recycle (all bitmaps zeroed),
   and any NEW bit is covered by the live-attempt / tenure /
   publication protocol.* Terminal retraction of the OLD obligation is
   therefore safe **iff** every local bit-setting path is mechanically
   covered by a live attempt, a tenure, or an already-published
   obligation. ACTION: fix the comment at dlm_caw.c:3616-3622, and audit
   every local bit-setting site to confirm that coverage.
2. **Claim-then-dispatch array: SAFE.** No chain-stability assumption
   found. Head inserts and other-entry unlinks do not invalidate a
   pinned claim; `lreq_gc`'s `**pp` re-walk from head is correct.
   Caveats to preserve: never move a pinned entry between buckets, never
   mutate `resource` in place, never touch `e` after `lreq_gc`.
3. **Gen split: SOUND**, modulo theoretical uint64 wrap. The worker's
   pin makes recycling-underneath impossible, so a `gen0` for resource R
   can never be validated against a recycled entry. Merge-then-retract
   cannot restore numerical equality. If an absolute proof is wanted:
   force shutdown at `owed_gen == UINT64_MAX` — **do not saturate**
   (a saturated gen stops changing and the stale-retraction guard fails).
4. **Failing the mount when the worker won't start: CORRECT.** Joining
   the owed worker before BAST: **NOT PROVEN, LIKELY WRONG** — see
   blocker 2.

## Non-blocking

- Make `lreq_owed_disp` / `lreq_owed_runs` atomic (CONFIRMS my C;
  non-blocking unless they drive policy/tests).
- **Preallocate the worker's slot buffer at thread start** — a cleanup
  mechanism that can be blocked indefinitely by `-ENOMEM` is wrong.
  `caw_owed_resolve` currently allocates per pass.
- Record real failure causes (last rc, first-obligation ts, CAW
  contention vs I/O error vs ENOMEM vs plan-suppressed).
- Remove or log the unused top-of-dispatch `hint` snapshot.
- Lifecycle assertions at collector exit: warn distinctly on a live
  publisher, `clr_active != 0`, `owed_busy`, or a count that changes
  after the final drain check.

## Next session's first job

Land blockers in this order (1, 5, 6 are local to the worker; 2 and 3 are
lifecycle/architecture and touch stop/mount):
**5 + 6 first** (smallest, purely inside the worker + a new
`lreq_clr_begin_existing`), then **1** (deadline plumbing, touches
`find_slot`/`caw_drop_own_waiter` signatures — the widest edit), then
**4** (owed-ready queue), then **2** and **3** together (they are one
lifecycle change: producer quiescence + terminal withdrawal).
Verify blocker 7 against dlm_caw.c:2105 before writing anything for it.

Closure for D-SAMENODE-WAITER-CANCEL-COLLISION still requires the sess113
debugfs exerciser — a green board CANNOT close it (sess111 measured the
reconcile arm entered 0 times on all 32 nodes).

---
name: ccloop-c7ee71c6-sess128-blocker1-deadline-LANDED
description: sess128: sess126 ruling blocker 1 (absolute deadline, no retry counts) LANDED on 0.11.444. Blocker 4 CONFIRMED real — sweep cursor does NOT advance i…
metadata:
  type: reference
tags: [mxfs, dlm-caw, sess128, owed-worker, blocker1, deadline, stop-ship]
---

# sess128 — ruling blocker 1 LANDED on 0.11.444

Tree `0.11.443` -> **0.11.444**, srcversion `3BBBB5F36CECFDD3A90159F`, builds
clean (only pre-existing warnings: the `mxfs_dlm_lkt_dump` prototype in dlm.c
and the compiler-differs note; neither in `dlm_caw.c`). NOT deployed; fleet
stays on 0.11.440. **Still STOP-SHIP** — 4 of the 7 sess126 blockers remain
(4, 2, 3, and 7's surviving half).

Continued D-SAMENODE-WAITER-CANCEL-COLLISION (ledger #16) rather than starting
at #1, same reason as sess119-127: the DLM core is mid-landing under stacked
stop-ship rulings and sess126 designated the landing order.

## What landed — the absolute deadline

An ABSOLUTE `mxfs_pal_time_ms()` deadline is plumbed
`sweep -> dispatch -> resolve -> find_slot_skip` and
`sweep -> dispatch -> drop_own_waiter -> read_slot/caw_slot/sleep`. Every
retry-COUNT policy on those paths is gone.

- **`find_slot_skip(..., uint64_t deadline)`** — checked before the hint read
  and before every probe iteration (span refills included). `find_slot()`
  passes 0; new `find_slot_deadline()` is the collector's entry point. Returns
  `-ETIMEDOUT`, deliberately NOT `-ENOENT`: `caw_owed_resolve`'s terminal proof
  needs a COMPLETE walk, and a truncated one cannot tell "absent" from "not
  reached". Only the collector ever passes a deadline — an acquire/release
  caller whose walk was cut short would be a correctness regression.
- **`caw_drop_own_waiter(..., uint64_t deadline)`** — `attempt < 1000` is now
  an unbounded `for` with the budget check at the TOP, before the slot read, so
  an expired deadline costs zero I/O. The retry nap is CLAMPED to the remaining
  budget. `-EBUSY` (attempts exhausted) no longer exists; `-ETIMEDOUT` replaces
  it and the dispatch treats it as "stop this pass", not contention
  (`if (rc && rc != -EAGAIN) break;`).
- **`deadline == 0` means "derive one"** for every non-collector caller,
  because the right budget depends on something only the function knows —
  whether the obligation got RECORDED. Two new constants:
  `MXFS_CAW_DROP_OWED_MS = 200` (registry present, so the worker owns
  persistence and this XFS thread leaves fast) and
  `MXFS_CAW_DROP_UNOWED_MS = 16000` (no registry => no worker, no record, no
  second chance; the honest restatement of the wall time the 1000-attempt loop
  actually consumed). The registry CAN be absent at runtime —
  `mxfs_dlm_caw_start` only fails the mount for a missing worker when
  `ctx->lreq` exists; an lreq allocation failure at start leaves the whole
  obligation mechanism inert.
- **`caw_owed_dispatch` returns `bool attempted`** and takes a deadline;
  re-checked before EACH mode, since one mode's CAS loop can eat the budget.
- **`caw_owed_release(ctx, e, bool attempted)`** — an entry claimed but never
  attempted (budget gone) is handed back with NO `owed_fails++` and NO backoff
  re-arm. Charging a retry to work that never ran walks a healthy obligation
  toward the P253 escalation bar for free.
- **`caw_owed_sweep(..., uint64_t deadline)`** — nonzero (the drain's shared
  deadline) also cuts the claim cap to `MXFS_CAW_OWED_DRAIN_CLAIM = 1`: the
  ruling's "process ONE bounded op per deadline check". Zero (running worker)
  keeps the 16-entry cap and gives each entry a fresh
  `MXFS_CAW_OWED_PASS_MS = 1000` budget.
- **Drain loop** paces with `DRAIN_STEP_MS` ONLY when the sweep claimed
  nothing. Pacing a productive sweep would cap the drain at
  `DRAIN_MS / STEP_MS = 100` entries regardless of speed.

### The honesty clause the ruling demanded

The ruling's NOTE: "if slot I/O itself can block past the deadline, we must not
advertise DRAIN_MS as a hard bound at all." It can — `mxfs_pal_bdev_read_prio`
hands the I/O to the block layer and it is not cancellable; a dead LUN's own
timeout is tens of seconds. So the header block, the worker comment and the
P254 log line all now say the deadline budgets the work **started**, and that
the true worst case is (deadline + one in-flight block-layer I/O). `read_slot`'s
retry loop does bail on `!ctx->running`, which is the cheap half the drain gets
for free. P245 and P252 both gained a clause naming rc=-110 as the budget, not
an I/O error.

## Blocker 4 is CONFIRMED REAL and UNFIXED — do not believe the cap=1 argument

I initially wrote (and then removed) a comment claiming `DRAIN_CLAIM = 1` makes
the drain round-robin. **It does not.** Traced at `dlm_caw.c` sweep loop:
`ctx->lreq_sweep = b` stores a BUCKET index, and the next sweep restarts at
`ctx->lreq[b]`, i.e. the HEAD of that chain. With cap=1, bucket 5 holding
pending X,Y,Z claims X, sets `capped`, stores b=5 — and the next sweep claims X
again. Y and Z starve exactly as the ruling says. Intra-bucket position is not
representable in the cursor, so no cap tweak can fix this.

Blocker 4 therefore still needs the ruling's actual prescription: a real
owed-ready QUEUE. Design worked out but NOT written:

- `struct mxfs_caw_lreq` gains `oq_next` / `oq_prev` (doubly linked so retract
  is O(1)) and `oq_queued`; ctx gains `owed_q_head` / `owed_q_tail`.
- INVARIANT: an entry is on the queue iff `lreq_owed_pending(e)` AND not
  `owed_busy`. Four transition points, all already under `lreq_lock`:
  merge -> enqueue tail; retract -> dequeue; sweep claim -> dequeue +
  `owed_busy = true`; release -> enqueue tail if still pending.
- That invariant is what keeps `lreq_gc` safe: gc's existing `!pending`
  condition then implies not-queued, so no entry can be freed while linked.
  If the invariant is weakened, `oq_queued` must become a gc refusal reason
  like `pin` — otherwise it is a use-after-free through the queue.
- Sweep pops from the head, bounded by the queue length at sweep start;
  ineligible entries (`clr_active`, or `!drain && now < owed_next_ms`) rotate
  to the TAIL, so each sweep examines each entry at most once and nothing
  starves. The hash table stays for LOOKUP only.

## Landing order from here

4 (owed-ready queue, designed above), then 2 and 3 TOGETHER (one lifecycle
change: producer quiescence + terminal withdrawal). Blocker 7 still needs its
false-positive check against `dlm_caw.c:2105` before anything is written.

Closure for D-SAMENODE-WAITER-CANCEL-COLLISION still requires the sess113
debugfs exerciser — a green board CANNOT close it (sess111 measured the
reconcile arm entered 0 times on all 32 nodes).

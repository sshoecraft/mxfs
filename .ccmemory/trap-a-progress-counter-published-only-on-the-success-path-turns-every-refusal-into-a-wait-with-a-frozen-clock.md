---
name: trap-a-progress-counter-published-only-on-the-success-path-turns-every-refusal-into-a-wait-with-a-frozen-clock
description: TRAP (s119): a retry loop that waits on "is the takeover making progress" never ends when the takeover keeps REFUSING, because the counter only moves…
metadata:
  type: feedback
tags: [dlm, wait, liveness, instrumentation]
---

# A progress counter that only moves on success cannot detect a refusal loop

## The shape

A retry loop is made "safe" by keying its patience on a progress counter
instead of on a budget: while the counter advances, the wait is legitimate
(someone is working); when it stops advancing for N ms, the wait is declared
stalled and ended.

The counter is incremented at the *single success return* of the worker
function, and every refusal path returns a negative instead — deliberately,
so that a pass which accomplished nothing is not reported as progress.

Both halves are individually correct. Together they mean: **a worker that
refuses forever looks exactly like a worker that has finished**, and the
waiter's stall clock is the only thing that could tell the difference — which
it does, and then, for a caller it cannot fail, it *resets the clock and waits
again*.

## Where it was found (MXFS, 0.89.45)

- `dlm/dlm.c:3558` — `ctx->takeover_pages_done++` is the only publisher, on
  `dlm_takeover_page`'s single success return.
- `dlm/dlm.c:2787` — the caller answers `-EINPROGRESS` (→
  `MXFS_DLM_RETRY_TRANSITION`) whenever that function returned anything but
  success-with-the-page-mine, and hands the frozen counter up as "progress".
- `dlm/dlm.c:8001-8035` — the retry loop detects the frozen counter after
  `MXFS_DLM_TRANSITION_STALL_MS`, logs `P960-AUTH-TRANSITION-STALLED
  fallible=0`, then sets `trans_t0 = now` and loops. `retries++` at :8054
  undoes the loop's own decrement, so the budget is never spent either.

Every refusal inside `dlm_takeover_page` is therefore an unbounded wait for a
non-fallible caller: the recovery-judging guard, a PREPARED page whose live
target never consumes it, an unresolved owner incarnation, a failed activate,
a failed import.

## Two aggravations worth checking for in any instance of this shape

- **The counter is global, the wait is per-object.** Progress on *unrelated*
  work resets the stall clock of a waiter whose own object is permanently
  stuck, so the stall is only ever detected once everything else is finished.
- **It propagates.** A node that is not the worker keys on a counter relayed
  in the worker's replies, so one stuck worker freezes every other node's
  waiters too, and they have even less evidence about why.

## What to do about it

When reviewing a "wait while progress advances" loop, ask the two questions
separately:

1. Which writes move the counter? If only the success path does, the counter
   answers "is anyone succeeding", not "is anyone working" — and the loop was
   written believing it answers the second.
2. What is the exit when the counter is legitimately static forever? "The
   caller keeps waiting and says so every 30 s" is not an exit.

A refusal that can persist by design needs its own terminal answer, not a
longer wait. Look for a comment in the refusing predicate that says the
condition holds "for as long as X stands" — that is the author telling you the
wait is unbounded.

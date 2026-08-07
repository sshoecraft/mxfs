---
name: ccloop-c7ee71c6-sess133-GPT-ruling-D2-D4-statemachine-plus-FAILSTOP
description: sess133 RULE-5 ruling: state machine APPROVED with conditions; D6 abandon-and-leak REJECTED as a known UAF — the answer is bounded escalation then LO…
metadata:
  type: reference
tags: [mxfs, dlm-caw, sess133, gpt-ruling, lifecycle, teardown, fail-stop, D2, D4, D6]
---

# sess133 — GPT ruling: the lifecycle state machine, and D6 ends in FAIL-STOP

Tree 0.11.449 at consult time. Consult covered (A) my D2/D3/D4 state-machine
design and (B) the D6 expiry semantics, where my code reading found the problem
is worse than the sess132 ruling stated.

## THE FINDING THAT DROVE PART B

If phase 2 gives up and RETURNS, phases 3–6 must be skipped (release_all would
race live producers; the census would be a lie), so the BAST poll thread and the
BAST multicast recv thread are still running. They call `ctx->bast_cb` =
`v5_bast_cb(v5ctx)`, which immediately calls `bast_notify_fn` /
`ag_bast_notify_fn` / `iclus_bast_notify_fn` — and **those closures point into
the XFS mount `mp`, which the VFS frees regardless of anything the DLM
decides**. Leaking the CAW ctx (`unsafe_to_free`) and even the v5 ctx does NOT
save it. Clearing `bast_cb` closes the future window but not the thread already
past the NULL test. And expiry means a wedged LUN, so the BAST threads are
wedged in the same I/O — "join them anyway" is another forever-wait.

## PART A — the state machine: APPROVED, with conditions

**A1 waiting is right, but:**
- `STOPPING`/`STOPPED` waiters must return the OWNER'S STORED VERDICT, read
  under `lreq_lock` — "verdict unmodified" is wrong if it means leaving the
  caller's output untouched.
- **The escalation path must never synchronously perform a WAITING stop.**
  Deadlock: owner waits → escalation work → withdraw → `mxfs_dlm_caw_stop` →
  waits for the owner to reach STOPPED. If the upper layer cannot avoid it,
  add an explicitly nonblocking `mxfs_dlm_caw_stop_try()` returning
  `-EINPROGRESS` on STOPPING. Do NOT weaken the normal stop API.
- "a STOPPING waiter is bounded by the owner" is **only true once every
  blocking phase has a bounded/fail-stop policy — phases 3 and 5 (the joins)
  can also block forever today**.
- Same hole for `STARTING`: waiting for `state != STARTING` is unbounded if the
  failed-start unwind joins a wedged transient thread.

**A2 `lreq_lock` is the right home.** No hazard from the owner's logical claim
(it does not hold the mutex across phases). Required: one locked operation for
STOPPING+ops_closed+running+seq; store the COMPLETE verdict BEFORE setting
STOPPED; broadcast after both are published; all waits are recheck loops;
`destroy()` inspects `unsafe_to_free`/verdict under the same synchronization.
**Do not use `volatile bool`** for the loop hint — use READ_ONCE/WRITE_ONCE (or
release/acquire). Serializing `stop()` does NOT serialize two `destroy()`
callers: keep the single-destroy contract explicit or add a refcount.

**A3 common body for NEW/START_FAILED is correct** (special-casing START_FAILED
as automatically clean would be wrong), provided: NEW→STOPPING elects an owner
exactly as RUNNING does; every teardown-referenced lock/list/handle is
initialized before the ctx is externally visible; joining an absent/unwound
thread is an explicit no-op; arming/joining an uncreated owed worker is a no-op;
`release_all` must not touch an uninitialized transport; **"release_all ran"
must mean its complete traversal FINISHED**, not that it was entered;
`release_on_stop` and resource-presence must be SNAPSHOTTED so they cannot
change during teardown. The D3 release term is otherwise sound, and
`census_left == 0` stays as an overall verdict term as well.

## PART B — D6: the answer is LOCAL FAIL-STOP

**B1. C is the only bounded safe answer.**
- A (wait forever) is memory-safe but retains the permanent kernel hang.
- **B (abandon + leak + neuter) is NOT ACCEPTABLE — "a known UAF is not an
  acceptable teardown policy."**
- C: on final expiry — (1) permanently mark the departure unclean, (2) do NOT
  run phases 3–6, (3) **do NOT publish STOPPED and do NOT return to
  put_super**, (4) invoke a NON-RETURNING local fail-stop (panic / emergency
  restart / watchdog reset) guaranteeing this kernel no longer touches shared
  storage. A filesystem withdraw is NOT equivalent: it neither proves the
  wedged threads are gone nor makes freeing `mp` safe.
- **The same rule covers EVERY teardown join whose target can touch storage or
  mount-owned state**: BAST poll, mcast recv, owed worker, failed-start unwind.
- Do NOT "bounded-join" by calling a blocking join and hoping. Split it:
  (1) publish the stop request and wake, (2) wait on a THREAD-EXIT COMPLETION
  with a deadline, (3) only join/reap once exit is known, (4) fail-stop if the
  completion never arrives.
- The 4th architecture (refcounted/revocable notification endpoint + SRCU +
  `synchronize_srcu`) can close the "past the NULL test" race but still does
  not solve an in-flight CAW/XFS op retaining `mp`. Until every such reference
  is structurally eliminated or pinned, RETURNING REMAINS UNSAFE.

**B2. The bound.** 155s is the **fault-detection/escalation threshold, not
permission to abandon**. At 155s: latch `quiesce_expired`, make a clean verdict
impossible for this attempt, ASYNCHRONOUSLY request force-shutdown/withdraw,
and start ONE final fail-stop grace. If quiescence + safe thread exit happen
during the grace, teardown may finish — but the sticky expiry still forbids the
clean GOODBYE. At grace expiry: mandatory local fail-stop.
**Do NOT use "SCSI EH has finished" as the second bound** — no portable upper
bound exists across SCSI EH / multipath / retries / driver bugs; it just moves
the unbounded wait down a layer. Use an explicit policy interval, 30–60s,
configurable, and it **must not be settable to infinite on a shared-write
clustered mount**. Total: `155s + bounded grace = mandatory fail-stop deadline`.

**B3. The CAW layer must enforce asynchrony ITSELF.** A synchronous call to a
contractually queue-only handler is insufficient — it makes the lower layer's
teardown liveness depend on upper-layer behaviour and lets a future handler
change introduce blocking/re-entry directly in the quiesce loop. Required:
latch one-shot bit + reason + timestamp under `lreq_lock`; queue a dedicated
work item AFTER dropping the lock; the work item invokes the v5 handler;
repeat observations are no-ops; explicit lifetime reference; not queued on a
workqueue the stop owner drains; no recursive waiting stop (A1).
**The quiesce loop only records and queues — it never invokes the handler.**
And the fail-stop deadline must NOT depend on the work item running: the stop
owner or an independent watchdog still enforces the terminal deadline.

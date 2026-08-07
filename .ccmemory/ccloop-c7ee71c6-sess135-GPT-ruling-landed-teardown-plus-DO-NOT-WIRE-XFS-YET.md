---
name: ccloop-c7ee71c6-sess135-GPT-ruling-landed-teardown-plus-DO-NOT-WIRE-XFS-YET
description: sess135 RULE-5 ruling on the LANDED 0.11.451 teardown: 3 stop-ship items. Wiring the XFS stuck-notify NAIVELY CREATES A UAF — do not wire until the d…
metadata:
  type: reference
tags: [mxfs, sess135, gpt-ruling, rule5, dlm-caw, teardown, stop-ship, uaf, escalation]
---

# sess135 RULE-5 ruling — review of the LANDED 0.11.451 teardown

Consult covered: (1) review the landed D2/D3/D4/D6 shape, (2) how to wire the
XFS end of the escalation, (3) the escalation never fires at runtime.

## THREE STOP-SHIP ITEMS

1. The XFS escalation endpoint is unwired — the required force-shutdown
   notification is a no-op. (Known; sess134 found it.)
2. **Runtime owed-stuck never escalates.** A live member can retain an
   uncleared bit indefinitely while continuing to mutate the filesystem.
   Unbounded cluster-liveness failure. NEW severity: this is the PRIMARY
   reason the callback exists, and it is the case that does not fire.
3. **The XFS lifetime argument is incomplete** unless the CAW/v5 deferred
   escalation work is itself synchronously drained.

## THE FINDING THAT CHANGES THE PLAN — DO NOT WIRE XFS YET

My proposed wiring (work_struct on xfs_mount, cancel_work_sync after
mxfs_v5_dlm_shutdown) was judged lifetime-safe ONLY if v5 shutdown gives a
stronger guarantee than it currently does. The UAF sequence:

    1. CAW queues escalation work holding a BARE ctx pointer
    2. v5 shutdown joins the owed worker
    3. v5 clears/frees callback state
    4. XFS cancels its own work and frees mp
    5. the previously queued CAW escalation work RUNS and dereferences
       v5/XFS data

"Owed worker joined and callback pointer NULLed" is NOT sufficient, and
`caw_teardown_escalate_queue()` can be called by the STOP OWNER, not only the
owed worker. Verbatim: **"Do not wire the XFS callback until that upstream
guarantee has been demonstrated. Otherwise the formerly dead callback chain
becomes a UAF path."**

So sess134's NOT-DONE item 1 must NOT be done as written. Prerequisite: an
explicit cancel/flush/reference protocol for `mxfs_pal_defer`'s item.

## 1a. The election's `lc == STOPPING` early return is WRONG — remove it

A caller is entitled to infer teardown is COMPLETE when stop() returns.
`stop(ctx); if (!unsafe_to_free(ctx)) free(ctx);` is unsafe if stop() can
return during STOPPING. Wait unconditionally for STOPPED; the phase deadlines
guarantee termination. Make `lreq_cond` MANDATORY whenever `lreq_lock` exists
(the `else break` path is unreachable for a published ctx — treat as an
invariant violation, not a degraded sync mode).

**Plus a defect I did not ask about:** fixing the wait does NOT make
concurrent destroy/stop safe. Owner can set STOPPED, unlock, broadcast,
return to destroy(), and FREE THE CONDVAR while a woken non-owner has not yet
reacquired the lock. Needs a `stop_callers` census or a real refcount — the
single-destroy contract only excludes two destroyers, not destroy() racing an
independent stop().

## 1b. `esc_at` is an expiry deadline, NOT a fail-stop deadline

Each `caw_join_bounded` starts a NEW full grace. Worst case: 155s + 45s
(phase 2) + 45s (bast_recv) + 45s (bast_poll) + 45s (owed_worker). The
"ONE ABSOLUTE deadline" claim in the sess134 memory is therefore FALSE as
implemented. Fix: compute `expire_at = t0+155s` AND `failstop_at = expire_at
+ grace` ONCE, pass both, every join gets only the time remaining before
`failstop_at`. Also audit phase 4: if `caw_release_all_body` can block or
retry unbounded, the teardown has no whole-operation bound regardless.

## 1c. Blanket `unsafe_to_free` — CORRECT, keep it

"Blocked in UDP recv" is not proof freeing is safe: the thread's stack holds
ctx and it touches ctx after recv returns. And the deferred item's bare
pointer means the latch protects more than the timed-out thread. Permanent
leak after any expiry is defensible. Do NOT clear the latch just because the
grace join later succeeded.

## 1d. Phase 2 / release-after-expiry

- Phase 2 cannot return with ops_active != 0 — CONFIRMED (relies on
  mxfs_pal_failstop being genuinely non-returning, which the macro's `for(;;)`
  fallback now guarantees).
- `left == 0` IS authoritative given the producer inventory is complete —
  with one condition to verify: **no deferred escalation callback itself
  publishes obligations.**
- `expired` should NOT suppress phase 4. CAW release writes are teardown
  cleanup, not continued mutation; skipping leaves strictly more bits on
  disk. But v5/XFS shutdown+withdraw must be idempotent/serialized because
  the escalation may be running concurrently at the XFS level.

## 1e. Ordering / wakeups

- Set STOPPED **and broadcast while holding lreq_lock**, then unlock (I do it
  after unlocking — predicate is safe, but the condvar's LIFETIME is not).
- Audit that nothing takes held.lock while holding lreq_lock: owed-worker
  completion, op leave/error paths, logging helpers, release-all callbacks,
  shutdown/withdraw callbacks.

## 2b. Once-only flag: use an explicit mount bit, not schedule_work

schedule_work coalesces only while pending/running; after the item finishes a
later notify re-queues it. `test_and_set_bit(MXFS_MOUNT_DLM_STUCK_QUEUED,
&mp->m_flags)`; the work must NOT clear it. Prefer a small state machine
ARMED -> QUEUED -> DONE, plus DISARMED so teardown can reject notifications.
Emit the probe only on the winning transition.

## 3. The runtime escalation — predicate must be TIME + ERROR CLASS, not retry count

"32 attempts" is coupled to backoff/scheduling and does not classify the
fault. Required classification, which the code does NOT currently make:

- **compare mismatch** — EXPECTED optimistic-concurrency outcome; reread and
  retry. NOT evidence CAW is broken.
- **transient transport/path error** — bounded path-recovery budget.
- **command timeout** — serious; count wall-clock + path recovery.
- **permanent/media/illegal-request/reservation error** — escalate at once or
  after a very short confirmation.
- **bit verified already clear** — obligation COMPLETE regardless of history.

Escalate on **per-obligation wall-clock age** (record when the node first
became obligated), not attempt count, because the property being protected is
bounded cluster progress. Escalate if ANY safety-relevant obligation exceeds
its deadline — distinct-stuck-count is telemetry/severity, not a precondition.

**32-node contention hazard:** deterministic capped 500ms retries can
SYNCHRONIZE across nodes and perpetuate CAW collisions. Add randomized jitter
to compare-mismatch retry. Mismatch starvation must still keep a finite upper
bound or the liveness guarantee is only probabilistic.

Correct escalation sequence: force-shutdown (stop mutating) -> continue
bounded DLM cleanup -> withdraw liveness -> fail-stop if those cannot
complete. Must NOT depend on teardown having started.

## 3c. Intermediate steps that are actually sound

Before the final deadline: stop new local acquires on the affected resource;
trigger path recovery/failover; promote the ratelimited warn to a once-only
high-severity event; randomized contention backoff; prioritize the oldest
obligation; optionally close DLM admission globally for a short final drain.

NOT sufficient: refusing new acquires on that resource (the on-disk bit
remains, peers still block); "poison this inode" (the lock may cover metadata
beyond one inode — ICLUSTER covers up to 32). **Slice-local self-fencing is
NOT a real safety operation unless MXFS has slice-scoped membership/fencing
with epoch purge — with only node-level liveness it is local refusal while
peers stay blocked.**

## The ruling's own rig-test list (item 10)

runtime permanent CAW EIO; runtime compare-mismatch storm with 32 synchronized
nodes; notify racing ordinary unmount; notify queued during v5 shutdown;
delayed upstream escalation work after callback disarm; second stop() caller
waiting while owner completes; timeout followed by grace-join success; work
cancellation while force-shutdown is already running.

---
name: ccloop-c7ee71c6-sess132-GPT-ruling-steps1-4-DEFECTS-plus-step5
description: sess132 RULE-5 ruling: the LANDED steps 1-4 (0.11.448) have 5 real defects incl. 2 blockers; step 5's threshold AND drain ceiling derivations both RE…
metadata:
  type: reference
tags: [mxfs, dlm-caw, sess132, gpt-ruling, blocker2, blocker3, lifecycle, teardown, stop-ship, escalation]
---

# sess132 — GPT ruling: steps 1–4 are DEFECTIVE as landed; step 5's two derivations are both rejected

Tree **0.11.448** at consult time. One consult covered both the review of the
sess131 landing and the step-5 design. **STILL STOP-SHIP.** Do NOT rig-cycle
0.11.448 — the ruling found defects in what is already in the tree.

Continued D-SAMENODE-WAITER-CANCEL-COLLISION (ledger #16), same reason as
sess119–131.

## PART 1 — DEFECTS IN THE LANDED CODE (sess131, 0.11.448)

### D1 (BLOCKER) — the fallback drain must be DELETED
`caw_owed_worker_fn` parks on `drain_armed` with a give-up of
`QUIESCE_MS + DRAIN_MS`, then "drains anyway". That fallback can fire while
`ops_active != 0`, while the BAST producers still run, and **before phase 4
executes** — so it drains, exits, and then phase 4's `release_all` publishes
into a registry **with no worker left to collect it**. That is precisely the
gap the whole restructure exists to close, reintroduced by the safety net.
Calling the census "not authoritative" does not repair it.

There is NO deadlock to protect against: while phase 2 is stuck, stop has not
reached `thread_join()` yet, so the worker may stay parked indefinitely.
**Fix: remove the give-up; drain only when `drain_armed`.**

### D2 (BLOCKER) — concurrent stop callers race the `!running` shortcut
Phase 1 sets `running = false` near the START of stop. A second caller then
takes the `!running` shortcut and returns **as though stop had completed**,
free to call destroy / free / read an intermediate verdict while the first stop
is still executing. `stop_ran` + the verdict are also tested and written
unlocked.

### D3 — `departed_clean` can be true when it must not be
1. **Suppressed release** (`release_on_stop == false`): `left == 0 &&
   rel_lost == 0` does NOT prove no bits were left, because nothing walked the
   tracked holdings. The verdict must carry a `release_clean` term:
   `release_on_stop ? release_completed_without_loss : verified_no_local_slot_state`.
   For a withdrawn mount, the conservative answer is to report the CAW
   departure UNCLEAN. (The v5 layer's `!withdrawn &&` masks it today — but the
   CAW-layer value is semantically wrong and another caller could misuse it.)
2. **Partially failed start** — wrote a slot / started one producer / created a
   registry entry, then failed before `running = true`. The shortcut calls that
   "never started ⇒ clean by construction". It is not.

### D4 — `running` cannot encode the lifecycle
Required: an explicit serialized state machine
`NEW / STARTING / RUNNING / STOPPING / STOPPED / START_FAILED`, one lock,
one stop OWNER on `RUNNING→STOPPING`, other callers wait or get a defined
"stop in progress", `STOPPED` returns the stored verdict unmodified,
`START_FAILED` runs stage-dependent cleanup and is NOT automatically clean.
Destroy must never infer from `running == false` that no stop thread is using
the ctx.

### D5 — the gate proves less than claimed
The locking argument is sound **for gated producers only**. Still required:
- a mechanical audit of every call site that can insert/merge an
  `mxfs_caw_lreq`, re-pend an entry, set on-disk bits whose later failure
  creates an obligation, or schedule deferred work that does any of those;
- an admitted op must hold its `ops_active` reference until all
  publication-capable DESCENDANTS finish — scheduling async work then calling
  `caw_op_leave` is a hole;
- joining the 2 BAST threads is sufficient only if they enqueue nothing onto
  another thread/workqueue that outlives them;
- classify completion callbacks, timers, socket callbacks, reconnect and
  error-recovery paths;
- **"no late obligation" ≠ "no late on-disk mutation"** — every op that can SET
  slot bits must be covered even if it cannot publish.
GPT wants a debug assertion at the central publication function: caller is an
admitted op, OR a registered not-yet-joined external producer, OR stop owns the
exclusive phase. Without it the 8-entry-point audit will regress.

### D6 — unbounded phase-2 wait inside put_super
Not continuing is correct; waiting forever in `put_super` is a kernel lifecycle
hazard (unmount and module unload blocked forever; uninterruptible LUN I/O
never observes cancellation; half-shut-down mount with BAST/membership/
heartbeat still alive). `unsafe_to_free` does not help — execution never
reaches destroy. **The 155s notifier must be ASYNC and idempotent**: as
written, phase 2 calls `caw_owed_fail_notify` SYNCHRONOUSLY, which once step 5
wires the callback re-enters filesystem shutdown while shutdown is already
running from put_super. Also verify the heartbeat thread, kept alive
deliberately, references no XFS structure put_super is dismantling.

## PART 2 — THE DRAIN BUDGET

GPT conceded its "~2 entries" arithmetic assumed a fresh PASS_MS per dispatch;
with the shared deadline one dispatch can eat all 2000ms. The concern stands.

- **(i) per-entry fairness ACCEPTED** — `min(shared_deadline, now + PASS_MS)`,
  rotate a still-pending entry behind the other eligible ones. Conditions:
  rotation must be real (not a hash-bucket artefact); the episode timestamp
  must survive claim/failure/requeue; no dispatch may START past the shared
  deadline; leave bookkeeping time for the final census; a cooperative deadline
  does not bound an uninterruptible block request.
- **(ii) scale-with-work ACCEPTED as a baseline, not a sizing proof** — use a
  SATURATING multiply; census `n` only AFTER producers are joined and phase 4
  has published. `n * PASS_MS` budgets one worst-case dispatch per entry, which
  is one fair pass, not enough retries to ride out transient contention.
- **(iii) `DRAIN_MAX_MS = 62000` REJECTED as derived.** 62s is only the
  DETECTION portion and it starts AFTER we stop heartbeating; fence, election,
  replay and purge follow. Draining 62s then dying puts recovery START at
  ~124s — past a peer's 120s wait. The real constraint is
  `DRAIN_MAX ≤ WAIT_TIMEOUT − DEAD_DETECTION − RECOVERY_BOUND − MARGIN`,
  i.e. `< 120000 − 62000 = 58000`, ≈53000 using UNLOCK_DEADLINE as margin, and
  less again once fence/replay is counted. **With the available constants there
  is NO positive ceiling that guarantees avoiding a peer timeout.** Derive it
  instead from: the peer-liveness objective + a bounded post-abandon recovery
  time, the unmount-latency contract, the storage stack's transient-recovery
  interval, and explicit operational policy — and SAY it is policy.
- **No-progress early exit: yes, but classify the evidence.** Terminal storage
  failure ⇒ abandon promptly. No successful slot I/O for a bounded
  storage-recovery interval ⇒ stalled LUN, stop early. Successful reads with
  CAS miscompares ⇒ live contention, keep going. A dispatch that reduces the
  registry resets the timer. Repeated identical hard errors exit sooner than
  repeated contention.

## PART 3 — STEP 5

- **(A) `ESCALATE_MS = WAIT_TIMEOUT + UNLOCK_DEADLINE = 125000` REJECTED.** It
  fires AFTER the peer it exists to protect has already timed out; the +5s is
  in the wrong direction, and the local unlock window OVERLAPS the peer wait
  rather than following it. Also `owed_since_ms` is stamped only after an op
  has already burned much of its unlock budget. Escalation is not
  instantaneous: `ESCALATE_MS + notify/shutdown latency + 62000 + fence/replay
  + margin < 120000` ⇒ **below 58s**, ≈53s provisionally, less once
  fence/replay is bounded. Derive from `WAIT_TIMEOUT − worst_case_action_to_
  purge − margin`; if action-to-purge cannot be bounded, state plainly that the
  threshold is POLICY, not a proof that peers are spared. Retry count stays
  diagnostic, never the primary trigger. No threshold helps a peer that was
  already waiting when the episode began.
- **(B) episode age ACCEPTED.** Must survive pending→claimed, failed dispatch
  and requeue, merges, rotation. May reset only after the old episode was
  POSITIVELY resolved. Entry delete/recreate must not reset age unless the
  on-disk residue was verified cleared. Monotonic clock.
- **(C) triggers ACCEPTED structurally**, but split the state:
  `owed_failed` / `runtime_escalation_queued` / `runtime_escalation_delivered`
  — a teardown latch must not suppress a required runtime force-shutdown.
  **The notify must NOT run synchronously in the owed worker**: if it reaches
  `xfs_force_shutdown` → `caw_stop`, phase 5 joins the CURRENT worker
  (self-join deadlock). Drain-expiry with NO upward callback is ACCEPTED
  provided the contract is written into the API: stop is called synchronously
  by the layer that consumes `departed_clean`, the latch is set before stop
  returns, no producer can follow the census, and EVERY caller honours the
  verdict.
- **(D) `xfs_force_shutdown(SHUTDOWN_META_IO_ERROR)` CONFIRMED over a bare
  withdraw** — the invariant is "local mutation and new DLM activity must be
  blocked BEFORE this node stops advertising liveness". But verify the ordering
  rather than trusting the precedent: the shutdown flag must be published to
  all mutation paths BEFORE the withdrawal. (VERIFIED in-tree this session:
  `xfs_do_force_shutdown` does `xfs_set_shutdown(mp)` at xfs_fsops.c:511 and
  only then `mxfs_dlm_shutdown_withdraw` at :529 — correct order.) The action
  must be QUEUED on a safe workqueue: once-only, holding a mount lifetime
  reference, safe against a concurrent ordinary unmount, cancellable without
  self-deadlock.
  **Proportionality upheld**: one stale resource kills every peer that needs it,
  so resource count is not a severity measure. The intermediates are rejected —
  refusing local acquires does not remove the stale bits, and "purge-self one
  slot" is either the same failing CAS or an unsafe force-clear. Fail-stop is
  the defensible response once bounded cleanup has failed.
- **(E) `mview` ACCEPTED as supplementary evidence only, and must NOT be named
  epoch.** Two nodes can share an `mview` for different memberships, differ for
  the same one, reset on restart, and observe changes in different orders — it
  cannot correlate a cluster event. Add: fs/cluster UUID, node boot/incarnation
  UUID, disklock slot generation / lease incarnation, resource identity,
  wall-clock alongside monotonic episode age, last successful I/O + last error,
  dispatch/retry count. **The absence of a committed membership epoch on the
  live CAW transport is itself a finding** (the real one, `struct
  mxfs_mepoch_rec`, belongs to net2, whose objects are not in the module Kbuild).

## WHAT LANDED THIS SESSION (plumbing only, behaviourally inert)

- `dlm_caw.h`: ctx fields `mship_view` / `mship_members` (lreq_lock-guarded,
  with the naming rationale); public `mxfs_dlm_caw_set_owed_stuck_fn` and
  `mxfs_dlm_caw_set_membership`, both documented as
  notification-of-a-decision-already-made.
- `dlm_caw.c`: both setters. `set_owed_stuck_fn` refuses to register once
  `ops_closed` (no late registration behind teardown).
- `v5_mount.c`: `dlm_stuck_notify_fn/_data` + `mship_view` on `struct
  mxfs_v5_dlm`; `v5_membership_beacon_caw` bumps the view and pushes it down.
- NOT yet added: the `mxfs_v5_dlm_stuck_notify_fn` typedef + setter in
  v5_mount.h (v5_mount.c references the typedef, so **the tree does not build
  until that is added**), the xfs-side handler, and every trigger.

## NEXT SESSION — order

1. **Fix the landed defects FIRST** (D1, D2 are blockers; D3, D4, D6 next).
   D1 is a small deletion. D2/D4 want the state machine.
2. Finish step 5 on top: derive the threshold as POLICY with the arithmetic
   written down (< 58s, provisionally ~50s), the deferred/queued escalation
   (never synchronous in the owed worker), the split escalation state, the
   drain fairness + saturating scaled budget + evidence-classified no-progress
   exit.
3. Re-consult before the rig cycle — this ruling changed the design again.
4. D-SAMENODE-WAITER-CANCEL-COLLISION still needs the sess113 debugfs
   exerciser; a green board CANNOT close it.

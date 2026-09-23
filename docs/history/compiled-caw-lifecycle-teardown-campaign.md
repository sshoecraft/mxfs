<!-- sess127-135: CAW owed-obligation lifecycle/teardown restructure — 7 blockers landed 0.11.443-451, GPT rulings D1-D6, PAL fail-stop, verification-debt… -->
# CAW owed-obligation lifecycle/teardown restructure (sess127-135, 0.11.443→0.11.452)

Continuation of D-SAMENODE-WAITER-CANCEL-COLLISION (ledger #16), landing the 7
blockers sess126's ruling ordered. Landing order throughout: 5+6, then 1, then
4, then 2+3 as one lifecycle change, then step-5 runtime escalation. Every
session in this arc is STOP-SHIP; closure additionally requires the sess113
debugfs exerciser regardless of board color (sess111 measured the reconcile
arm entered 0 times on all 32 nodes — a green board proves nothing about this
defect). Fleet stayed on 0.11.440 through the entire arc.

## sess127 (0.11.443) — blockers 5 and 6 `docs/history/docs/history/docs/history/compiled-caw-lifecycle-teardown-campaign.md`

Blocker 5: `caw_owed_dispatch` handed already-read flags back into
`caw_drop_own_waiter` as `want`, whose only effect was an UNCONDITIONAL
`owed_gen++` via `lreq_owed_merge` — republishing obligations already
serviced, and desyncing `owed_gen` so a concurrent genuine local clear would
find the token stale and re-owe completed work. Fix: new
`lreq_clr_begin_existing` (snapshots `owed_gen`, no merge, no bump);
`caw_drop_own_waiter`'s `want` param replaced by a `collector` bool; per-mode
re-read of the owed/waiter bitmaps under lock, intersected with the
top-of-dispatch snapshot, before each mode.

Blocker 6 (condvar lost wakeup): broadcasts fire outside `lreq_lock`
(deliberate — avoids blocking the waker), but the worker did an unconditional
wait after reacquiring, so a publication landing between "decided to park" and
"parked" was lost for a full `IDLE_MS`. Fix: `lreq_owed_work_seq` bumped
inside the same locked critical section as every runnable-making event
(merge, `lreq_clr_end`, finish-with-owed, stop); `caw_owed_sweep` samples
`seq0` inside the same locked walk that picks the claim set; park predicate
is `running && seq0 == work_seq`; `next_due` (earliest backoff floor, capped
at IDLE_MS) replaces the fixed BUSY_MS/IDLE_MS cadence.

## sess128 (0.11.444) — blocker 1 `docs/history/docs/history/docs/history/compiled-caw-lifecycle-teardown-campaign.md`

Absolute `mxfs_pal_time_ms()` deadline replaces every retry-count policy on
`sweep→dispatch→resolve→drop_own_waiter→find_slot`. `find_slot_skip` returns
`-ETIMEDOUT`, deliberately not `-ENOENT`: the collector's terminal proof needs
a COMPLETE walk, and a truncated one can't distinguish "absent" from "not
reached" — only the collector ever passes a deadline. `deadline==0` means
"derive one": `MXFS_CAW_DROP_OWED_MS=200` when a registry entry exists (a
worker owns persistence, so the XFS thread can leave fast) vs
`MXFS_CAW_DROP_UNOWED_MS=16000` (no registry ⇒ no second chance). `-EBUSY`
retired in favor of `-ETIMEDOUT`. `caw_owed_release(attempted=false)` charges
no `owed_fails`/backoff — a claim that never ran must not be scored as a
failed retry. Honesty clause demanded and written into P245/P252/the header:
the deadline budgets work STARTED, not completed — an in-flight
uncancellable block-layer I/O can still exceed it.

Blocker 4 CONFIRMED real, not a false alarm: `DRAIN_CLAIM=1` does not make
the drain round-robin, because `ctx->lreq_sweep` stores a bucket index and
the next sweep restarts at that bucket's HEAD — intra-bucket position isn't
representable, so bucket contents beyond the first starve regardless of cap.
Real fix (designed, not yet written): a doubly-linked owed-ready queue,
invariant "entry queued IFF pending && !busy" enforced at exactly 4
transition points, all already under `lreq_lock`.

## sess129 (0.11.445) — blocker 4, producer inventory, teardown-order audit `docs/history/docs/history/docs/history/compiled-caw-lifecycle-teardown-campaign.md`

Owed-ready queue landed: `owed_q_head/tail/n` replace the bucket cursor;
`lreq_oq_sync` re-establishes the invariant and is called after EVERY
owed-bit write (2 sites) and EVERY `owed_busy` write (2 sites) — audited to
be the only 4 places drift could occur. Memory-safety property, not just
scheduling: `lreq_gc` refuses on the derived condition AND on `oq_queued`
directly, so weakening the invariant later leaks instead of use-after-frees.
Sweep bounded by `owed_q_n` at sweep start, declined entries rotate to tail —
the entire anti-starvation argument.

Producer inventory (line-verified, the key fact that unblocks 2/3): obligation
publication happens at exactly 2 entry points — `caw_slot_clearing` and
`caw_drop_own_waiter` reachable only from `mxfs_dlm_caw_lock`/`_convert` (the
collector's own call takes the non-publishing `lreq_clr_begin_existing` path).
So "quiesce the producers" reduces to an admission gate + in-flight counter on
exactly those two functions — no thread-by-thread BAST/transport argument
needed.

Blocker 3's escalation channel already exists and needs only a wall-clock
trigger: `mxfs_dlm_shutdown_withdraw` → `schedule_work` →
`mxfs_v5_dlm_shutdown_withdraw` (sets `withdrawn`, `mxfs_disklock_withdraw`,
`mxfs_scsipr_unregister`, `mxfs_discovery_stop`) is already a
non-sleeping/lock-safe context.

Teardown-order defect found: in `mxfs_v5_dlm_shutdown`, the GOODBYE broadcast
and heartbeat-slot release both run BEFORE the drain — the node announces
departure while its bits are still uncollected. `mxfs_dlm_caw_release_all`
also runs before the drain and publishes nothing on its own CAS-retry
failures (separate gap, same family as blocker 5).

Blocker 7 verified: `lreq_owed_retract`'s per-episode reset is correct as-is;
the surviving concern (`owed_since_ms`, needed so continuous publication
can't suppress wall-clock escalation) is deferred to blocker 3.

## sess130 (0.11.446) — GPT ruling on blockers 2+3 `docs/rulings/blockers-2-3-lifecycle.md`

Proposed design (gate admission, wait in-flight→0, keep `release_all` where
it was — BEFORE the drain — then drain) was WRONG: a race exists today where
`release_all` clears every holder bit while an acquire already inside the
door continues, succeeds, re-takes the bit, and publishes NOTHING (success
needs no cleanup) — quiesce then sees zero in-flight, drain finds no
obligation, node sends GOODBYE while still holding a bit on disk.

Corrected mandatory order: close admission → wait for all already-entered
ops → stop/join other publication-capable producers → run `release_all`
EXCLUSIVELY → publish every `release_all` failure → drain under the absolute
deadline → iff all clear: GOODBYE + clean slot release; else: withdraw/fence,
no clean departure. Other rulings that reshaped the design: publication must
precede the global in-flight decrement in the SAME lock critical section; a
quiesce timeout must NOT let teardown proceed (mark failed, withdraw, keep
ctx/registry/transport alive rather than free under a live user — the wait
is bounded in practice by `MXFS_CAW_WAIT_TIMEOUT_MS`=120000, so the quiesce
deadline must exceed 120s); GOODBYE+clean-release belong only on the
clean-success branch (a false clean departure authorizes an unsafe peer
reclaim); TWO escalation triggers (runtime age AND drain-deadline-with-residue
— arithmetic warning: DRAIN_MS=2000 against PASS_MS=1000 admits only ~2
entries per drain, so any nonempty queue can withdraw even when every op
would have cleared given more time); the notification callback must never be
the safety latch — record failed/closed/unclean SYNCHRONOUSLY under the lock,
then invoke; diagnostics need the membership epoch, node/mount identity, and
which trigger fired; episode age is a deliberately conservative attribution
(state that in the log line, don't claim precision it doesn't have); residue
check must scan the authoritative registry under lock, not queue emptiness.

Code facts banked: `lreq_join`/`lreq_finish` call sites fully enumerated and
matched; `caw_drop_own_waiter` has 5 call sites, not 4; the
schedule-after-cancel race GPT worried about closes itself for free because
`put_super` clears `m_mxfs_dlm` and `cancel_work_sync`s the withdraw work
BEFORE calling `mxfs_v5_dlm_shutdown`, so `mxfs_dlm_shutdown_withdraw`'s
early-return on null ctx prevents any re-arm; `mxfs_dlm_caw_destroy` calls
`release_all` AFTER `mxfs_dlm_caw_stop` (i.e. after the worker is joined) —
anything it publishes there is uncollectable by construction and it defeats
the withdrawn-suppression the v5 layer relies on (marked for deletion);
`MXFS_CAW_WAIT_TIMEOUT_MS=120000`, `UNLOCK_DEADLINE_MS=5000`,
`MAX_RETRIES=100` are the constants every derived threshold must anchor to
(GPT explicitly rejected "5 minutes" and the old 32-pass constant as
undereived). Landed this session: state fields only
(`ops_closed/active/refused`, `departed_clean` starts false,
`owed_failed*`, `owed_stuck_fn/data`) and the episode clock
(`owed_since_ms` stamped only on the not-pending→pending edge) — fully inert.

## sess131 (0.11.448) — lifecycle restructure steps 1-4 `docs/history/docs/history/docs/history/compiled-caw-lifecycle-teardown-campaign.md`

Step 1 (admission gate): `caw_op_enter/leave` wraps 8 entry points as thin
`*_body` wrappers so no exit path can leak the count (`unlock`,
`purge_node`, `purge_dead_nodes` are pure delegations that inherit the gate —
verified line by line, not omitted). `P255-CAW-OPS-UNBALANCED` on imbalance.

Step 3 (release_all publishes failures): `caw_owe_residue` +
`caw_release_all_body`; the resource is captured at the LAST GOOD read, never
re-read off `cur_slot` afterward (a later failing read may have scribbled the
buffer — an obligation keyed on garbage is worse than none); alloc failure at
the top counts every tracked slot as lost (`P257-RELEASEALL-NOMEM/-LOST/-RESIDUE`).

Step 2 (`mxfs_dlm_caw_stop` restructured into 6 phases): close admission
(ops_closed+running=false+seq bump, one CS) → quiesce on `ops_active==0`
(UNBOUNDED on purpose per the ruling's item 2 — exclusivity in phase 4 must
hold however long quiesce took) → join the BAST threads → EXCLUSIVE
`caw_release_all_body` gated by `release_on_stop` → arm drain, join owed
worker → census+verdict in one CS. Quiesce-stuck latches at
`MXFS_CAW_QUIESCE_MS`(155s, derived), notifies once, regripes every 30s.
Phase 6's escalation deliberately does NOT notify (post-join; the recorded
state, not the callback, is what must carry the failure out — closing the
channel there is what makes state-not-callback the real latch). `stop_ran`
distinguishes never-started (clean by construction) from already-torn-down
(verdict stands); `destroy()` always calls `stop()` a second time so it can't
overwrite a refusal with a vacuous pass. `destroy()`'s own unconditional
`release_all` DELETED (uncollectable + defeats withdrawn-suppression);
honors `unsafe_to_free` by leaking (`P260-CAW-CTX-LEAKED`) rather than
freeing a live ctx.

Step 4: `mxfs_v5_dlm_shutdown` drops its own `release_all`; calls `caw_stop`
EARLY — before GOODBYE, with lease/discovery/heartbeat still up, since the
drain needs this node to still be a live member for slot I/O.
`depart_clean = !withdrawn && caw_departed_clean()` computed once, gates
BOTH the GOODBYE broadcast and `mxfs_disklock_release_slot` (both previously
tested only `!withdrawn`). Legacy `dlm/mount.c:2778` path needed an explicit
`set_release_on_stop(true)` since the default is fail-closed and destroy no
longer releases. Step 5 (runtime escalation, blocker 3 proper) not yet
written.

## sess132 — two GPT consults; steps 1-4 ruled DEFECTIVE; step-5 derivations rejected `docs/rulings/steps1-4-defects-plus-step5.md` `docs/history/docs/history/docs/history/compiled-caw-lifecycle-teardown-campaign.md`

Do-not-rig-cycle finding: the just-landed 0.11.448 has defects.

- **D1 (blocker)**: the owed worker's fallback drain (gives up after
  `QUIESCE_MS+DRAIN_MS` and drains anyway) can fire before phase 4 even runs
  — draining the pre-release set, exiting, and leaving phase 4's
  `release_all` to publish into a registry with NO collector. Exactly the bug
  the restructure exists to close. Fix: delete the give-up; wait
  unconditionally on `drain_armed`.
- **D2 (blocker)**: concurrent `stop()` callers race the early `!running`
  shortcut — a second caller can return as though teardown completed while
  the first is still running; `stop_ran`/verdict are tested and written
  unlocked.
- **D3**: `departed_clean` can be wrongly true — the suppressed-release case
  (`release_on_stop==false`) proves nothing about tracked holdings, and a
  partially-failed start is not automatically clean. Needs a `release_clean`
  term split by `release_on_stop`.
- **D4**: `running` cannot encode the lifecycle; needs the explicit state
  machine (`NEW/STARTING/RUNNING/STOPPING/STOPPED/START_FAILED`) with one
  lock and one stop owner.
- **D5**: the admission gate proves less than claimed — needs a mechanical
  audit of every call site that can publish/re-pend/set on-disk bits or
  schedule deferred work that does so; an admitted op must hold its
  reference until publication-capable descendants finish; "no late
  obligation" ≠ "no late on-disk mutation".
- **D6**: an unbounded phase-2 wait inside `put_super` is itself a kernel
  lifecycle hazard (unmount/module-unload blocked forever); the 155s
  notifier must be ASYNC, not synchronous (sync reentry into shutdown while
  shutdown is already running).

Drain budget: per-entry fairness accepted (rotate a pending entry behind
others within `min(shared_deadline, now+PASS_MS)`); scale-with-work accepted
as a baseline only, not a sizing proof; **`DRAIN_MAX_MS=62000` REJECTED as
derived** — 62s is only the detection portion, and draining 62s before dying
puts recovery start at ~124s, past a peer's 120s wait; real constraint is
`DRAIN_MAX ≤ WAIT_TIMEOUT − DEAD_DETECTION − RECOVERY_BOUND − MARGIN` (<58000
with current constants) — **no positive ceiling with the available constants
guarantees avoiding a peer timeout**; must be stated as policy, not derived.

Step 5 threshold: **(A) `ESCALATE_MS=WAIT_TIMEOUT+UNLOCK_DEADLINE=125000
REJECTED** — fires AFTER the peer it's meant to protect has already timed
out; correct derivation is `WAIT_TIMEOUT − worst_case_action_to_purge −
margin`, below 58s (~53s provisional), and must be documented as policy if
action-to-purge can't be bounded. **(B)** episode age accepted (must survive
pending→claimed/failed/requeue/merge, reset only on positive resolution).
**(C)** triggers accepted but state must split into
`owed_failed`/`runtime_escalation_queued`/`_delivered`; notify must NOT run
synchronously in the owed worker (self-join deadlock if it reaches
`caw_stop`). **(D)** `xfs_force_shutdown(SHUTDOWN_META_IO_ERROR)` confirmed
over a bare withdraw — verified in-tree that `xfs_set_shutdown` precedes
`mxfs_dlm_shutdown_withdraw` (correct order for "stop mutating before
stop advertising liveness"). **(E)** `mview` must never be called an epoch
(the real committed epoch, `struct mxfs_mepoch_rec`, belongs to unbuilt net2)
— its absence on the live CAW transport is itself a finding.

Landed as 0.11.449: ONLY D1 fixed (verified no deadlock exists: `drain_armed`
and the worker join happen in order on the same stop thread, so an unarmed
worker parked forever blocks nobody) + fully inert escalation/membership
plumbing (`mship_view/members`, `set_owed_stuck_fn` refuses once
`ops_closed`, v5 stuck-notify typedef/setter, `v5_membership_beacon_caw`).
D2-D6 remain open, D2 still a blocker, no trigger wired.

## sess132 fencing note

`docs/history/docs/history/docs/history/compiled-fence-inflight-exclusion-test-design.md`
and `docs/rulings/step4-inflight-exclusion-test-blocked.md`
belong to a different defect (D-PR-FENCE-PREEMPT-WITHOUT-ABORT) landed in the
same session — see `docs/history/docs/history/compiled-fence-inflight-exclusion-test-design.md`.

## sess133 — state machine ruling + D6 fail-stop semantics; PAL primitives landed `docs/rulings/d2-d4-statemachine-plus-failstop.md` `docs/history/docs/history/docs/history/compiled-caw-lifecycle-teardown-campaign.md`

Finding that reframed D6: if phase 2 gives up and returns, the BAST poll and
multicast-recv threads are still running (uninvolved by design) and their
callbacks point into the XFS mount `mp` — which the VFS frees regardless of
what the DLM decides. Leaking the CAW ctx does NOT save it; clearing the
callback pointer only closes the FUTURE window, not a thread already past
the null check; and since expiry implies a wedged LUN, "join them anyway" is
just another forever-wait.

Part A (state machine) approved with conditions: STOPPING/STOPPED waiters
must return the owner's STORED verdict read under lock; the escalation path
must NEVER synchronously perform a WAITING stop (deadlock risk — add a
non-blocking `stop_try()` if unavoidable, don't weaken the normal API);
"a STOPPING waiter is bounded by the owner" is only true once every blocking
phase (3 and 5, the joins) also has a bound+fail-stop policy; the same
initialization-completeness requirement applies to the NEW/START_FAILED
common teardown body; `release_on_stop` and resource-presence must be
snapshotted so they can't change mid-teardown.

Part B (D6): the only acceptable answer is LOCAL FAIL-STOP. Waiting forever
keeps the hang; "abandon+leak+neuter" is explicitly rejected — "a known UAF
is not an acceptable teardown policy." On final expiry: mark unclean, skip
phases 3-6, do NOT publish STOPPED or return to `put_super`, invoke a
NON-RETURNING fail-stop (panic/reset) — a filesystem withdraw is not
equivalent since it neither proves the wedged threads are gone nor makes
freeing `mp` safe. Same rule for every teardown join touching storage or
mount state. Bounded-join shape: publish stop request + wake → wait on a
thread-exit completion with a deadline → join/reap only after known exit →
fail-stop if the completion never arrives. 155s is the escalation threshold,
not permission to abandon; + a bounded grace (30-60s, must not be settable to
infinite on a shared-write clustered mount) = the mandatory fail-stop
deadline. Do not use "SCSI EH finished" as a second bound (no portable upper
bound across SCSI EH/multipath/retries). The CAW layer must enforce
asynchrony itself: latch one-shot bit+reason+timestamp under lock, queue a
dedicated work item AFTER dropping the lock, and the quiesce loop only
records and queues — it never invokes the handler; the fail-stop deadline
must not depend on that work item ever running.

Landed as 0.11.450: `mxfs_pal_failstop` (noreturn: `pr_emerg` then
`panic()`/`abort()`) and `mxfs_pal_defer` (one-shot self-freeing work item on
`system_unbound_wq` GFP_ATOMIC, or a detached pthread; negative return means
UNDELIVERED, never the latch) added to `pal/pal.h` — required in PAL because
architectural invariant 4 forbids dlm/ from touching kernel APIs directly.
`enum mxfs_caw_lifecycle` declared in `dlm_caw.h`, unused. Verified in-tree
that the escalation→withdraw→re-entrant-stop deadlock GPT warned about does
NOT currently exist (`mxfs_dlm_shutdown_withdraw` never calls `caw_stop`) —
write this as an invariant when the trigger lands, since it's easy to
reintroduce silently. PAL already had the bounded-join primitive
(`mxfs_pal_thread_join_timeout` on an exit completion) — phases 3/5 only need
to switch to it plus add fail-stop on expiry. Also found, not yet fixed:
`mxfs_dlm_caw_create`'s stop_lock/cond failure unwind leaks several
allocations (OOM-path, unreachable in practice); `dlm/mount.c:2507`
(`err_dlm`) stops without `set_release_on_stop(true)`, suppressing release on
a failed mount.

## sess134 (0.11.451) — D2/D3/D4/D6 landed `docs/history/docs/history/docs/history/compiled-caw-lifecycle-teardown-campaign.md`

`ctx->lc` state machine added, `stop_ran` deleted. `start()`:
NEW→STARTING→RUNNING or →START_FAILED on either unwind (never back to NEW —
a failed start may hold published residue). `stop()`: owner election at the
top; NEW/STARTING/RUNNING/START_FAILED converge on one teardown body; the
election critical section also sets `ops_closed`/`running=false`/
`release_all_done=false`/bumps `work_seq` and SNAPSHOTS `release_on_stop`
into `release_now`. Phase 6 stores the complete verdict THEN sets STOPPED in
one CS, broadcasts after unlock. `departed_clean`/`unsafe_to_free` signatures
changed to read under lock (const dropped, one caller updated).

Correction to a prior plan, load-bearing: `caw_op_enter` must NOT be
tightened to `lc==RUNNING` as sess133 suggested — `purge_dead_nodes_ex` (a
gated entry point) runs between `create()` and `start()`, so a RUNNING-only
predicate would refuse it and break every mount. Landed predicate:
`(NEW||STARTING||RUNNING) && !ops_closed` — still strictly tighter than the
old `!ops_closed` since START_FAILED now refuses.

D3 release term: `quiesced && !teardown_expired && !owed_failed && left==0 &&
rel_lost==0 && (release_now ? release_all_done : held_at_stop==0)`.
`release_all_done` set only at `caw_release_all_body`'s final
successful-traversal exit (its NULL-ctx/alloc-failure exits leave it false).
`held_at_stop` snapshotted under `held.lock` BEFORE `lreq_lock` — lock
ordering invariant: always held→lreq, never the reverse.

D6: intended as ONE absolute deadline for the whole teardown
(`t0+155s`=escalation, `+grace`=fail-stop), not per-phase.
`caw_teardown_expire_locked` is a sticky latch: sets `unsafe_to_free` FIRST
(what makes the deferred item's bare ctx pointer safe to touch — destroy
leaks rather than frees), then `teardown_expired`+`owed_fail_latch`, and
returns whether to queue the one-shot escalation via `mxfs_pal_defer` — the
quiesce loop only records and queues, never invokes the handler.
`caw_join_bounded()` replaces all 3 `pal_thread_join` calls (bast_recv,
bast_poll, owed_worker) AND the failed-start unwind join.
`mxfs_caw_failstop_grace_ms` module param, default 45000, clamped [5000,
300000] on read (forbidding an infinite setting on a shared-write clustered
mount). `dlm/mount.c:2507` fixed per the sess133 finding.

Objtool trap (cost half an hour — do not repeat): `__noreturn` on
`mxfs_pal_failstop` broke objtool's noreturn detection because objtool
checks a hardcoded list and can't learn noreturn-ness across translation
units; an explicit `return;`, `unreachable()`, and moving the call off the
function tail all failed (GCC elides/sinks around them). Fix: drop the
attribute, rename the implementation to `mxfs_pal_failstop_fn`, and make
`mxfs_pal_failstop` a macro that calls the fn then does
`for (;;) mxfs_pal_cond_resched();` — objtool accepts the self-branch as a
valid end of flow.

Not done: the escalation chain still dead-ends (no caller of
`mxfs_v5_dlm_set_dlm_stuck_notify` anywhere in-tree, so
`dlm_stuck_notify_fn` is always NULL); `create()`'s stop_lock/cond unwind
leak from sess133 still open. Nothing rig-verified — D2/D3/D4/D6 stay OPEN
under the zero-defect bar until a test exercises the cause.

## sess135 — ruling finds the landed 0.11.451 still broken; verification-debt reckoning `docs/rulings/landed-teardown-plus-do-not-wire-xfs-yet.md` `docs/history/docs/history/docs/history/compiled-caw-lifecycle-teardown-campaign.md`

Three stop-ship items reviewing 0.11.451: (1) XFS escalation endpoint still
unwired (known); (2) **new, primary-severity finding**: runtime owed-stuck
NEVER escalates — a live member can hold an uncleared bit indefinitely while
continuing to mutate the filesystem; this is the actual reason the callback
exists and it's the case that doesn't fire; (3) the XFS lifetime argument is
incomplete unless the CAW/v5 deferred escalation work is itself
synchronously drained.

**DO NOT WIRE XFS YET** — this reverses the sess134 not-done plan. Proposed
wiring (a `work_struct` on `xfs_mount`, `cancel_work_sync`ed after v5
shutdown) is UAF-unsafe: CAW queues escalation holding a bare ctx pointer →
v5 shutdown joins the owed worker → v5 clears/frees callback state → XFS
cancels its own work and frees `mp` → the ALREADY-QUEUED CAW escalation work
runs and dereferences freed v5/XFS data. "Owed worker joined + callback
NULLed" is insufficient because `caw_teardown_escalate_queue` can be called
by the STOP OWNER too, not only the owed worker. Prerequisite, not yet built:
an explicit cancel/flush/reference protocol for the `mxfs_pal_defer` item.

Further defects found in 0.11.451: **1a** — the election's `lc==STOPPING`
early return is WRONG; a caller is entitled to infer teardown is COMPLETE
when `stop()` returns, so it must wait unconditionally for STOPPED (the
phase deadlines already guarantee termination); even fixed, concurrent
`destroy()`/`stop()` is still unsafe (owner can set STOPPED, unlock,
broadcast, return, and free the condvar while a woken non-owner hasn't
reacquired the lock) — needs a `stop_callers` census or a real refcount.
**1b** — sess134's "ONE ABSOLUTE deadline" claim is **FALSE as implemented**:
each `caw_join_bounded` call starts a fresh full grace, so worst case is
155s + 45s×4 (phase2 + 3 joins), not 155+45 total. Fix: compute
`expire_at=t0+155s` and `failstop_at=expire_at+grace` ONCE, pass both, each
join gets only the time remaining before `failstop_at`; also audit phase 4
(`release_all`) for its own bound. **1c** — blanket `unsafe_to_free` is
correct, keep it: "blocked in UDP recv" isn't proof freeing is safe (the
thread's stack still holds ctx); don't clear the latch just because a later
grace-join succeeds. **1d** — phase 2 confirmed cannot return with
`ops_active!=0` given the failstop macro is genuinely non-returning; expired
must NOT suppress phase 4 (skipping leaves strictly more bits on disk); v5/
XFS shutdown+withdraw must be idempotent/serialized against a possibly
concurrent escalation. **1e** — STOPPED must be set and broadcast WHILE
HOLDING `lreq_lock` (predicate is safe unlocked, the condvar's lifetime is
not); audit that nothing takes `held.lock` while holding `lreq_lock`.
**2b** — the once-only escalation flag should be an explicit mount bit, not
bare `schedule_work` (which coalesces only while pending — a later notify
after completion re-queues); use an ARMED→QUEUED→DONE(+DISARMED) state
machine.

**3** — runtime escalation predicate must be TIME + ERROR CLASS, not retry
count: classify compare-mismatch (expected optimistic-concurrency outcome,
not evidence of breakage), transient transport error (bounded path-recovery
budget), command timeout (serious — count wall-clock + recovery), permanent/
media/illegal-request error (escalate at once), bit-verified-already-clear
(obligation complete regardless of history). Escalate on **per-obligation
wall-clock age**, not attempt count. 32-node hazard: deterministic capped
retries can synchronize across nodes and perpetuate CAW collisions — add
jitter to compare-mismatch retry. Correct sequence: force-shutdown (stop
mutating) → bounded DLM cleanup → withdraw liveness → fail-stop if
incomplete; must not depend on teardown having already started. Named
architectural gap: slice-local self-fencing is NOT a real safety operation
without slice-scoped membership/fencing + epoch purge — with only
node-level liveness, it's local refusal while peers stay blocked.

**Verification-debt finding (separate note, same session)**: fleet was on
0.11.440 while the tree was at 0.11.452 — 12 versions of landed change
(sess112-135: lreq registry, owed-ready queue, D1 fix, lifecycle restructure,
PAL fail-stop/defer, D2/D3/D4/D6 state machine, create() unwind fix) never
deployed or boarded. Under the zero-defect bar, verification requires a test exercising
the cause, so all 12 versions were unclosable by construction until
deployed; 20 sessions of design/landing had not moved the open-defect count
and could not have. Rule adopted: do not land a 13th unverified version
before boarding — `run.sh` deploys and asserts the loaded srcversion on every
node itself, so the rig cycle IS the deployment. Plan: 2-node smoke →
32-node board → harvest the new teardown probes every unmount now exercises
(`P258-QUIESCE-STUCK/-LATE`, `P259-DEPART-UNCLEAN`, `P260-CAW-CTX-LEAKED`,
`P261-ESCALATE-UNDELIVERED`, `P262-TEARDOWN-JOIN-STUCK/-LATE`,
`P253-OWED-STUCK`) since a 32-node board runs `stop()` 32 times — the
D2/D3/D4/D6 exerciser already available for free. Caveat: sess113's earlier
"no-go for the 32-node rig" verdict was about the sess112 fix being
inadequate (aggregate-counter sampling can't establish exclusive ownership),
not a standing prohibition on boarding — sessions 114-135 already reworked
exactly that.

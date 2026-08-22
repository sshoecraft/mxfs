---
name: ccloop-c7ee71c6-sess381-GPT-ruling2-fence-retry-mechanics
description: sess381 RULE-5 ruling 2: the fence-retry state machine — invert the bit to MAY_HAVE_RUN, descriptor is the durable queue, never re-fire expire_cb, 4…
metadata:
  type: project
tags: [sess381, rule5, gpt-ruling, fencing, retry, 381, disklock]
---

# sess381 RULE-5 ruling 2 — the fencing retry/takeover state machine

Serves `D-FENCE-PRECONDITION-FAILURE-RECORDED-TERMINAL-381`. Consulted with the
concrete MXFS machinery (recov_desc stages, `recovery_fence_intent` return
codes, `fire_dead`'s `ctx->monitored[slot] = false`, the reporting-only
`ctx->blocked[]`).

Verdict: `FENCING` is being treated as durable work ownership, but there is
neither a durable retry source nor a takeover path, and a one-shot heartbeat
callback can never provide either.

## The bit goes the OTHER WAY — this corrected my design

Not `F_FENCE_PRECOMMAND` (set at intent, cleared before submit). Use a
**monotonic** `MXFS_RECOV_F_FENCE_CMD_MAY_HAVE_RUN`, set durably *immediately
before* handing the CDB to the transport and never casually cleared. Reasons:
my version needed a mutable bit among sticky ones and had to be cleared on a
path that must not fail; `MAY_HAVE_RUN` is clear on every early return by
construction, and its name stops future code reading it as proof that
submission *did* happen.

Required order: install FENCING intent (bit clear) → all pre-command checks →
set the bit durably + stamp → wait for durable completion → revalidate
ownership/term → hand CDB to transport. Crash before the flag write = nothing
submitted; crash after it but before submission = conservatively ambiguous, and
that window is the right failure mode.

Three durable states suffice: `FENCING`+bit-clear (guaranteed nothing
submitted), `FENCING`+bit-set (reconcile before assuming anything),
`stage >= FENCED` (certificate). In memory keep the 3-value phase but name the
middle one **MAY_HAVE_SUBMITTED** — a transport handoff does not prove target
execution. `VERIFIED` != `FENCED`: certification is a separate step.

## Retry driver: (b) with the ON-DISK DESCRIPTOR as the queue

- **(a) re-arming the heartbeat monitor is ACTIVELY DANGEROUS.** `expire_cb`
  means "a live identity became dead, do one-time retirement"; it does not mean
  "a durable operation needs another attempt". Re-firing it risks repeating
  dead-node retirement, notifications, slice-recovery creation, purge, successor
  rebasing and monitor sample transitions, and entangles fencing liveness with
  heartbeat sampling. Wrong control boundary even if each step is idempotent.
- **(d) fencing from the mount admission path is ALSO DANGEROUS**: the node is
  not yet a member, its own PR authority may not be established, repeated mount
  attempts become a fencing storm, admission and recovery locks can invert, and
  an external actor can induce destructive storage ops by retrying mounts.
- **(b) is right, but a pure in-memory latch is insufficient** — if the prover
  crashes after arming it, the retry request vanishes, which is the same class
  of bug being fixed. `stage == FENCING` on disk IS the durable outstanding
  work; the latch is only a wake-up accelerator. 64 slots is cheap to scan.
  Keep the worker OUT of the heartbeat monitor state machine.
- **(c) the elected replayer KICKS the worker**, never fences inline — inlining
  couples the recovery-execution lease to the fencing-attempt lease and invites
  lock inversion / circular progress dependencies. One fencing worker, several
  wake-up sources.
- Certification must fire an explicit `v5_fence_certificate_ready(slot, victim,
  epoch)` to wake blocked recovery. It must NOT repeat `v5_note_dead_node()`.

## Retry policy

Backoff is liveness policy, not a correctness lease: immediate, 250ms, 500ms,
1s, 2s, 4s, 6s, capped, ±20% jitter, with a global PR-op limit so 32 survivors
don't hammer the target. Retry immediately on membership change, reservation
restoration, local registration, recovery-owner change, replayer discovery, or
an administrative retry. **Never give up on an attempt count or elapsed time.**
A non-retryable invariant violation enters an explicit durable state
(QUARANTINED + reason), never "stop scheduling but log as if recovery is
automatic".

## Stale-attempt takeover (`-EBUSY` forever is its own defect)

Pre-command takeover needs, atomically in one CAS: still FENCING; observed
fence_term/prover/victim/epoch unchanged; lease abandoned; **and the old prover
definitively ineligible — absent from live membership or under a different
incarnation.** Elapsed time alone is NOT a correctness lease: a paused-but-live
prover can resume and submit after a time-based takeover, giving dual
authority. If a live node's fencing thread is merely wedged, fail-safe blocking
beats dual submission. Do not reuse `MXFS_RECOV_ABANDON_MS` unless its clock and
pause assumptions genuinely apply to the attempt lease.

## Takeover after MAY_HAVE_RUN — the highest-risk part

Never reset to "safe precommand" by bumping the term. The successor
**reconciles**: obtain a coherent PR snapshot (complete untruncated READ KEYS,
READ RESERVATION, own registration present, expected Write Exclusive form,
stable generation across the compound observation — one truncated or changing
response is never absence). Then:

- **victim key ABSENT** proves present exclusion *only if* MXFS separately
  prevents the retired incarnation from re-registering; that anti-rejoin
  property must be explicit. Certify under a kind meaning "verified exclusion
  from a coherent PR state after an earlier command may have executed" — never
  claim this node completed a P&A it did not observe.
- **victim key PRESENT** does not prove no old command is still in flight.
  Before another P&A you need a bound covering transport timeout, target
  completion, fabric error recovery, local abort/drain, and the dead prover's
  inability to submit. Without such a bound, stay in reconciliation.
- **inconclusive** → stay FENCING/MAY_HAVE_RUN and retry; never convert a
  transient PRIN failure into operator-only recovery.

## Post-PREEMPT verification

Yes, make it stricter than PROUT GOOD — but **only after the reconciliation
worker exists**, or it becomes a new permanent-blocking path. A verification
I/O failure after submission leaves `FENCING`+`MAY_HAVE_RUN` and retries
VERIFICATION, not resubmission — that is "outcome not yet verified", not
"proved but unrecorded". Even a failed certificate WRITE should retry
(re-verify, re-CAS) rather than going straight to operator-only; today's
`P238-FENCE-UNRECORDED` is too pessimistic.

## Caller shape

Replace the obscure `<0 / 1` with `V5_FENCE_CERTIFIED / PENDING / FATAL`.
One-time retirement + one-time recovery enqueue may still happen on PENDING
(every recovery gate refuses to pass FENCING anyway); what must never happen is
re-running the DEATH TRANSITION to retry the fence.

## Messages

Report durable phase + scheduler state, never infer retryability from
`fence_kind`. `P238-FENCE-PENDING ... phase=PRECOMMAND reason=NO_RESERVATION
command_may_have_run=no retry=automatic next_retry_ms=2000`. Reserve
`P238-FENCE-BLOCKED ... retry=manual quarantined=yes` for when automatic
scheduling has actually stopped. `P236-CLAIM-UNCERTIFIED` should carry stage,
term, prover+incarnation, phase, lease age, next retry, takeover eligibility,
and mount=deferred.

## Landing sequence (risk-ranked, highest first: post-submit reconciliation)

1. **Increment 1 — fixes the exact observed defect**: in-memory phase; durable
   `MAY_HAVE_RUN`; set before every state-changing CDB; descriptor-driven fence
   worker; retry of locally-owned FENCING/MAY_HAVE_RUN=0; certificate-ready
   wake-up; messages.
2. **Increment 2** — pre-command stale takeover (dead/incarnation-changed prover
   only).
3. **Increment 3** — MAY_HAVE_RUN reconciliation. Needs the most adversarial rig
   fault injection.
4. **Increment 4** — make post-PREEMPT verification mandatory.

Explicit warning to carry forward: **do not claim the general "permanently
unmountable" outcome is eliminated until Increment 3 and certificate-write
retry are also in.** Increments 1+2 remove it only for PRE-COMMAND failures.

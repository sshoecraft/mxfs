---
name: ccloop-c7ee71c6-sess381-summary-two-criticals-closed-fencing-lifetime
description: sess381 final: two criticals root-caused, fixed and rig-verified (WE-AR reservation lifetime + fence retry state machine); 0.17.0; board 27/27; open=…
metadata:
  type: project
tags: [sess381, summary, 381, fencing, scsipr, fixed-and-verified]
---

# sess381 — the fencing-lifetime session

Build went 0.15.10 -> **0.17.0 sv 7BE80C7FD64AF310791A322**. `MXFS_PROTO_GEN`
4 -> 5. Board 27 PASS / 0 FAIL / 1 POLICY at 32/caw, twice (0.16.1 and 0.17.0).
Ledger: **open=52 of 115** — two criticals CLOSED, three new entries filed.

## What was actually wrong, and how small the trigger was

Answering step 0 of `#379` produced a root cause far worse than the entry
claimed. MXFS reserved the shared LUN with **WE-RO (0x05), a single-holder
type**, and retires its own registration unconditionally at `put_super`. SPC
releases a registrants-only reservation when its holder's registration goes.

**Measured: one node's routine clean unmount — `real 0m0.056s`, 0.49s wall —
took the LU from a held reservation to NONE, with 31 nodes still mounted and
registered. Nothing re-reserved. 30 minutes later a different node was killed
and the whole cluster could not fence it.** No mass departure, no dirty slice,
no crash. sess379 had seen the same `NO_RESERVATION(8)` after a 28-of-32 storm
and could not explain it.

Then the transient became permanent: the fence returns `NO_RESERVATION`
**before** any PREEMPT is submitted — nothing consumed, victim key intact — but
the outcome was published as a durable terminal guard and **nothing in the tree
ever retried it**. The heartbeat monitor's `fire_dead` sets
`ctx->monitored[slot] = false` immediately before firing `expire_cb`, so a death
fires it exactly once, ever; `ctx->blocked[]` is a purely reporting array.

## Two closures, both FIXED AND VERIFIED

**`D-PR-RESERVATION-SINGLE-HOLDER-UNMOUNT-DISARMS-FENCING-381`** — reserve
WR_EX_AR (0x07) behind the proto-gen bump; `held` decided by TYPE not by the key
(SPC reports the holder key as **0** under all-registrants — measured); RESERVE
return values no longer discarded; conflict read back and classified; admission
gate observes *before* it acts (`P304-PREOBSERVE`) instead of validating a
reservation it just created; both Write Exclusive forms accepted in the fence
and cert paths; `SARK == own key` refused; and a **latent user.c bug** —
`cdb[2] = (type & 0x0F) << 4` put the type in the SCOPE field on every PROUT.

**`D-FENCE-PRECONDITION-FAILURE-RECORDED-TERMINAL-381`** — the ruling's
Increment 1: `enum mxfs_fence_phase` in memory, `MXFS_RECOV_F_FENCE_CMD_MAY_HAVE_RUN`
on disk (armed on the last line before the PROUT, and the command is not issued
if it cannot be made durable), a fence-retry worker whose **queue is the on-disk
descriptor**, and a per-slot single-prover guard.

## The thing the rig caught that code review did not

Nine WE-RO type tests, not seven. I found seven by grep and missed the two in
`dlm/disklock.c` (~5007, ~5261) — the certificate minter and its verifier. On
the first patched build the fence **PROVED** exclusion and the minter then
refused to certify it (`P236-FENCE-NO-RESV resv_type=0x07` /
`P238-FENCE-UNRECORDED`), which is the *worst* outcome available: the victim key
is consumed by then. Only a real fence on a real cluster surfaced it.

## Two corrections I took from the RULE-5 rulings

1. **The durable bit goes the other way.** I proposed `F_FENCE_PRECOMMAND` (set
   at intent, cleared before submit); that needs a mutable bit among sticky ones
   and must succeed at clearing on a path that must not fail. `MAY_HAVE_RUN` is
   monotonic and clear-by-construction on every early return.
2. **Re-arming the heartbeat monitor to retry is actively dangerous.** I was
   about to do it. `expire_cb` means "one-time identity retirement"; re-entering
   it repeats dead-node retirement, notifications, slice-recovery creation, purge
   and successor rebasing. Driving retries from mount admission is equally wrong
   — a non-member must not become a fencing authority.

I also **retracted a claim of my own**: I filed "`-EBUSY` forever, no stale-attempt
takeover exists" and then found `mxfs_disklock_recovery_fence_takeover()` fully
wired at `v5_mount.c:~3783`, gated on `v5_node_is_dead`. My first grep only
looked inside `fence_intent`. The real gap there is narrower and is filed.

## Verification (both tests are in the repo and re-runnable)

`tests/fence_lifetime_ab.sh` replays the exact bricking sequence — PASS on three
disjoint node sets. `tests/fence_precondition_retry.sh` removes the reservation
out of band with a scratch key, kills a node, and restores it: the fence hit
`NO_RESERVATION(8)`, published `P238-FENCE-PENDING ... command_may_have_run=no
retry=automatic next_retry_ms=277`, re-drove itself 4× with visible backoff, and
**9 seconds after the reservation came back, certified with zero operator
action**.

**A harness lesson worth the same weight as the code:** the first run of that
test FAILED, and the failure was `virsh destroy` leaving the domain wedged in
"in shutdown" with the guest still running and serving I/O. No node ever died,
and the test scored the absence of a fence as a defect in the code under test.
It now polls `virsh domstate` until "shut off" and aborts with an explicit
HARNESS/HOST FAULT verdict. (clyde still has `test5` stuck in that state; the
guest is healthy and is a working cluster member. Do not retry the destroy —
RULE 2c.)

## Filed

- `D-FENCE-POSTSUBMIT-AMBIGUITY-NO-RECONCILIATION-381` (critical) — the
  `MAY_HAVE_RUN` half has no reconciliation, and `fence_takeover` does not
  consult the bit before issuing a fresh P&A. This is the ruling's Increment 3
  and its **highest-risk** item.
- `D-PR-RESERVATION-HEALTH-UNMONITORED-AFTER-MOUNT-381` (high) —
  `validate_admission` has exactly one call site, the mount path. 31 nodes ran
  for 30 minutes on an unreserved LUN and none of them noticed.
- `#379` rescoped to arm (B): WE-AR does **not** close it — a node that retires
  its key while leaving a dirty slice still leaves nothing to preempt.

**Do not read either closure as "fencing is sound".** The permanently-unmountable
outcome is eliminated for PRE-COMMAND failures only.

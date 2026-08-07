---
name: ccloop-c7ee71c6-sess121-GPT-ruling-blocker2-owed-redesign
description: sess121 RULE-5 ruling on blocker 2: intent-first is right, but retraction needs target-scope + generation, lreq_plan must go PURE, and owed_slot over…
metadata:
  type: reference
tags: [mxfs, dlm-caw, lreq-registry, sess121, gpt-ruling, blocker2, owed-cleanup, stop-ship]
---

# sess121 RULE-5 ruling — blocker 2 (guaranteed-progress owed cleanup)

I proposed a 3-part fix: (A) intent-first owed publication, (B) precise
retraction on confirmed clear, (C) executor in the existing BAST poll thread.
Verdict: **direction correct, would NOT approve as written.** A is right, B is
UNSOUND as stated, C needs a dedicated worker — and a NEW release blocker was
found in existing code.

## A — intent-first: ACCEPTED, with two conditions

Closes the orphan race *provided C guarantees an executor* (A makes the work
discoverable; C makes it run).

1. **Do NOT start a second clearer while `clr_active != 0`.** Two concurrent
   CAW clearers are *probably* disk-safe (same target, per-iteration re-derived
   plan, all mutation by CAW, idempotent on already-clear bits) — but there is
   no benefit and it "substantially complicates owed retraction". Rule:
   `lreq_finish` may claim deferred work only when `attempts==0 && clr_active==0
   && pin==0 &&` eligible owed work exists. If `clr_active != 0` it leaves the
   published owed work alone and WAKES THE WORKER. When a clearer closes its
   window with `attempts==0` and owed work left, IT wakes the worker.
2. **Publication and window-open must be ONE atomic transition** under one
   `lreq_lock` acquisition: merge target-scoped intent → bump its generation →
   claim `clr_active` → take the pin → unlock → I/O. Ideally retraction +
   `clr_active--` + wakeup decision are likewise one critical section.

The 200ms registry scan may remain as a RECOVERY NET but must not be the normal
handoff mechanism.

## B — retraction: UNSOUND AS STATED (release blocker)

My claim ("owed is a statement about on-disk state, so any party confirming the
bit clear may retract") is only PARTIALLY correct. The flags also mean
*prospective* things: a clearer intends to clear but has not yet; clearing was
REFUSED because another local op may still publish/adopt; clearing must wait on
a tenure/attempt condition. So unconditional retraction on a fresh read is
unsafe.

**The concrete race:** A reads the waiter bit clear → B publishes a NEW
`owed_waiters` intent → A takes the mutex and clears the shared boolean. A has
erased B's newer obligation with a proof that PREDATES B's intent. Same race
exists after A's successful CAW (an intent can be installed between the CAW
linearization point and A's mutex-protected retraction).

**Required:** an owed GENERATION (per target, optionally per bit class).
Publish/merge bumps it under the mutex. An I/O iteration captures {target
identity, applicable generation, plan}, does the read/CAW, then retracts a bit
ONLY IF (i) the proof concerns the same target/incarnation, (ii) the generation
is unchanged, and (iii) the CURRENT plan permits discharging it. Explicitly:
**do not retract an obligation the current plan still REFUSES merely because the
bit happens to be clear** — a refusal for "another attempt is mid-adoption" is a
future publication hazard, not existing disk dirt.

**Make `lreq_plan()` PURE — remove every owed-state side effect.** Intent
merging happens explicitly once at operation opening; retraction explicitly
after proof. *That is what closes the Q3(b) audit item.*

## C — executor: NOT the BAST poll thread

A 1000-CAW destructive retry loop in the BAST poll/callback thread risks
delayed lock revocation, head-of-line blocking behind path failover, dependency
cycles (clear progress needing FS activity a BAST triggers), poll starvation and
unfairness across entries. **Separate per-ctx kthread or dedicated workqueue.**
BAST thread may DISCOVER and wake; it must not execute.

- Scheduling: immediate wakeup when work becomes runnable or a window closes
  with `attempts==0`, PLUS periodic scan as a missed-wakeup safety net.
- Claim: under `lreq_lock`, atomically set pin/busy, unlock, bounded work,
  re-lock to unpin and decide rescheduling.
- Retry: bounded I/O per dispatch (not 1000 in one go), randomized/exponential
  backoff, CAPPED so it keeps retrying, counters + ratelimited logs.
- **Escalation must never mean dropping the owed record.** No retry loop can
  clean up during permanent LUN/path failure. The guarantee must be: *never
  silently abandon cleanup while this node remains an active member — either
  clear it, or transition into a cluster recovery/membership state that makes
  the bit reclaimable* (withdraw membership / fence / fail the mount).
- **Teardown:** "until the mount stops" is INSUFFICIENT. Do not stop the worker
  while the node is still cluster-visible with owed bits. Graceful teardown must
  drain the owed cleanup OR withdraw membership so peers may ignore/clear our
  bits. A clean kthread stop alone does not solve the phantom-bit problem.

## 4 — `owed_slot` overwrite: NEW RELEASE BLOCKER (pre-existing code)

One overwriteable `owed_slot` per entry + shared owed booleans cannot express
two outstanding targets. Failure ordering: obligation recorded for the CURRENT
slot → a stale clearer records the OLD slot and overwrites `owed_slot` → the
worker reads the old slot, sees a resource mismatch, skips → **the current
slot's obligation has lost its location.** The reverse ordering strands the old
target or spins forever. "A recycled slot's bits are not ours" discharges only
the OLD target — it does not prove the shared flags do not also describe the
same resource in a NEWER slot.

Acceptable designs: (1) treat `owed_slot` as a HINT and resolve the resource's
canonical slot afresh every deferred pass (needs a proved at-most-one-live-slot
invariant + defined tombstone/recreate ABA handling); (2) **owed records keyed
per target — {resource, slot index, slot generation/incarnation} — so multiple
outstanding targets coexist and discharge independently**; (3) a slot
incarnation number in the on-disk slot and in the owed target.

## 5 — further invariants demanded before implementation

- **A.** Every path that can set our waiter / EX-waiter / holder bit must obey an
  ordering compatible with clear-window retraction. CAW prevents lost disk
  updates but NOT a stale completion erasing a newer in-core obligation. If a
  live attempt may publish after a refusal/read proof without publishing a new
  intent, either its publication advances an applicable sequence, or retraction
  stays forbidden while that attempt makes the plan refuse.
- **B.** `memcmp(resource)` detects reuse by a DIFFERENT resource but not
  tombstone→recreate of the SAME resource id, relocation-and-return, or reuse
  with a new lock epoch. Resource id alone may not be sufficient target identity.
- **C.** Worker claim: select under the mutex, set pin/busy BEFORE retaining the
  pointer, never hold the mutex across I/O, unpin + reschedule under the mutex.
  "Entries with owed work are un-GC-able" is NOT enough — the worker can retract
  the last owed flag while still holding a raw pointer. The PIN must cover the
  whole unlocked use.
- **D.** A resource mismatch must have a TERMINAL transition — a deferred pass
  cannot "skip" forever or the executor spins permanently.
- **E.** Uncertain CAW completion: infer NEITHER success nor failure. Retain the
  obligation and verify by a later read.
- **F.** Fairness: one hot resource losing CAWs constantly must not block every
  other entry's cleanup. Bound each claim by attempts or elapsed time; rotate.

## Approval shape (all 8 required)

1. target-scoped intent + window open, atomic.  2. `lreq_plan` side-effect-free.
3. no deferred cleanup while another clearer is active on the entry.
4. owed generation/epoch.  5. retract only on matching proof + unchanged
generation + currently-permitting plan.  6. `owed_slot` demoted to a hint with
canonical resolution, or multi-target records.  7. dedicated worker: immediate
wakeup, periodic fallback, bounded dispatch, persistent retry, escalation.
8. teardown drains owed work or withdraws membership.

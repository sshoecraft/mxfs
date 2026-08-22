---
name: ccloop-c7ee71c6-sess382-GPT-ruling3-grant-progress-publication
description: sess382 RULE-5 ruling 3 (incident474 hole c / c2): progress goes in a dedicated per-node single-writer table, one entry per outstanding BAST; progres…
metadata:
  type: project
tags: [mxfs, incident474, rule5, gpt-ruling, liveness, progress]
---

# sess382 RULE-5 ruling 3 — where grant progress lives, and what counts as progress

Context: hole (c) is now **reproducible** (`tests/hold_grant_liveness.sh`,
`mxfs.hold_grant_fault_ino`): a holder that stays mounted and beating while
refusing to release drove a waiter to `P-WAIT-EXTEND ... el_ms=120159` and a
129.6 s acquire. **New nuance the sess214 ruling lacked: the holder's fs was
fully SERVICEABLE — only that one grant was stuck. So c1 cannot catch it and c2
is the load-bearing half.** Ruling confirms that reprioritization.

## Q1 Placement — NOT the CAW slot

Rejected: a counter in the CAW slot or its `pad0` (reproduces the hot-LBA
serialization already measured — 59,742 ms on a contended slot vs 3 ms), and
**rejected: deriving progress from slot `generation`, holder bitmaps,
timestamps or heartbeat beats** — a frozen generation is equally consistent with
"useful off-slot AIL/log work" and "infinite retry loop", and generation can move
for unrelated waiter activity.

Preferred: a **dedicated per-node single-writer progress page/table** (A/B pair,
whole-page CRC, monotonic `publication_seq`, `node_boot_epoch`), written at HB
cadence plus at transitions (BAST ack/drain start, terminal release, shutdown).
**No write per AIL item or retry** — in-memory events fold into the next
publication. The HB record advertises support + format + latest
`publication_seq`. Carving the eviction ring again is only "acceptable for an
initial bounded implementation" and is worse (one descriptor is not enough;
recovery mode must not hide progress). This is an on-disk protocol change ⇒
`MXFS_PROTO_GEN` bump; a `feat_flags` bit may advertise support but must not
pretend no format negotiation is needed.

## Q2 Binding — one entry per outstanding BAST, not one node-wide counter

A node-wide counter is insufficient (progress elsewhere while this grant rots).
Minimum binding tuple:

```
node/mount epoch + canonical_resource_id(32B, the SAME id the CAW slot uses)
+ grant_cookie (holder-generated, never reused within the boot/mount epoch)
+ acquire_slot_generation (supporting evidence only — can wrap)
+ bast_request_id { requester_node, requester_boot_epoch, request_seq }
+ drain_epoch (the fixed obligation snapshot; changes if the drain is rebuilt)
```

A descriptor found **without acknowledgement of the current BAST** does not
authorize an extension. Publish `RELEASED/RETIRED` durably **before** the old
grant incarnation can be reused. Publish an entry for every grant with an
outstanding BAST (QUEUED/DRAINING/UNLOCKING/RELEASED/FAILED); "the oldest BAST"
is insufficient. On table full: explicit `OVERFLOW`, treat unrepresented grants
as **no verified progress**, never silently rotate.

## Q3 Progress = monotonic closure of a FIXED obligation ledger

**Event counting is not sufficient** — txn commit, log force, AIL op, iflush
attempt, re-log, retry counter, worker wakeup can all tick forever in a loop.

On BAST accept: block new obligations (or classify their creation as failure),
snapshot a drain epoch and its completion targets, publish a monotonic rank over
that **fixed** set. Phases must be finite and monotonic:

```
DRAIN_ACCEPTED -> NEW_DIRTYING_BLOCKED -> TXN_OBLIGATIONS_CLOSED
 -> LOG_TARGET_DURABLE -> AIL_OBLIGATIONS_CLOSED -> IFLUSH_OBLIGATIONS_CLOSED
 -> WIRE_UNLOCK_ENTERED -> SLOT_RELEASE_COMMITTED
```

**Critical rule: work does not count if it merely replaces an old obligation
with a new equivalent one.** For our 700-iteration re-log: re-logging must not
increase progress; committing the retry txn must not; moving an item to a new
LSN must not if that also moves the target. Retries are telemetry and may
trigger escalation, but never authorize an extension. (Note: sess382's change
(C) — the drain's re-log no longer creates obligations — is already this rule.)

## Q4 Escalation ladder when a serviceable holder stops progressing

There is **no safe "revoke just this grant"** while the holder can still issue
I/O. Ladder: (1) verify + re-challenge with a fresh targeted BAST, bounded;
(2) targeted local intervention on the holder (prioritize the release worker,
block new ops on that resource, restart the release machine from a documented
idempotent checkpoint) — bounded, and repeated kicks must not each restart the
budget; (3) quarantine the resource or quiesce the mount, publish `WITHDRAWING`;
(4) holder self-withdrawal / mount force-shutdown — **sacrifice the affected
mount before the whole node**; (5) external SCSI-PR fencing only if withdrawal
is not acknowledged or I/O cessation cannot be proven.

**Expiry does not mean the waiter may assume ownership.** It means stop
extending and begin holder-directed recovery. The waiter must not be killed as
the corrective action, and the grant must not transfer before holder exclusion.
An absolute deadline is still required or the ladder becomes the new 480 s loop.

## Q5 Rollout and the decisive falsifier

publish-only → shadow gate → enforce on injected faults → subset → cluster-wide,
always keeping the absolute deadline. Do not enforce while ordinary waits often
yield UNKNOWN (missing entry, overflow, publication delay, version mismatch).

**Primary false-negative falsifier:** a material population of cases where the
shadow policy would have denied for "no verified progress" but the holder then
completed the same grant incarnation normally, without intervention, withdrawal,
fault disarm, or any newly observed qualifying advance. That is a hard stop.
(Completion after manually disarming a deliberate fault must be classified
separately — it is not evidence the denial was wrong.)

**Progress false positives** are the more dangerous direction for this defect: a
livelock that keeps advancing rank, re-logging counted as advancement, unrelated
resource activity accepted, or an old publication surviving release/reacquire.

Board tests named: serviceable stuck grant; 700-iteration re-log loop; slow but
convergent drain; long indivisible legitimate op; several simultaneous BASTs;
release/reacquire ABA; torn publication; withdrawal fault; hot-slot contention
(no new holder CAWs); publication overflow.

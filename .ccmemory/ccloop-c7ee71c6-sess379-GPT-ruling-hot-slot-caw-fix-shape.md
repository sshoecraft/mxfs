---
name: ccloop-c7ee71c6-sess379-GPT-ruling-hot-slot-caw-fix-shape
description: sess379 RULE-5 ruling on D-HOT-SLOT-CAW-SERIALIZES-LUN-PER-LBA-379: fix order, the gate+per-node-reader-record format, and why "skip release-all" is…
metadata:
  type: project
tags: [ruling, gpt, rule5, sess379, caw, hot-slot, 379, format]
---

# sess379 RULE-5 ruling — fixing the hot-slot CAW serialization

Second consult of sess379, on **D-HOT-SLOT-CAW-SERIALIZES-LUN-PER-LBA-379**.

## Verdict on the attribution

"More than merely consistent" — resource specificity, dependence on concurrent
writers, nonlinear participant scaling, removal by staggering, harmlessness of
reads alone, temporal correlation with target aborts/TMFs, and a protocol that
predicts retry amplification on precisely that record. Enough to treat the
bitmap/CAW protocol as the dominant cause.

**Two qualifications — the ledger has been corrected for both:**

1. **The `.mus_probe` stat control is NOT conclusive LBA isolation.** Two
   `stat()` calls can differ in cache state, lock state, and *whether they issue
   a SCSI command at all*. A 3 ms stat does not prove I/O to the other LBA was
   healthy. The conclusive form is a **direct READ(16) to a hot LBA and to a
   cold idle LBA on the same LUN, issued during the storm, with
   dispatch-to-completion timing**.
2. **The 60 s quantum does NOT prove a command was lost.** A timeout clips the
   tail of a queueing distribution into a fixed recovery penalty, which is
   exactly why there is no middle ground. Determine whether the 60 s is
   dispatch-to-timeout, post-timeout EH, or a sum of timers.

## Cheapest discriminating instrumentation

Per-CDB at the initiator: queued / dispatched / completed timestamps, opcode,
LBA + length, tag, SCSI status and sense, host result, MISCOMPARE count,
timeout callback, abort/TMF initiation and result, retry reason. That
separates: not dispatched (software queue) · dispatched-late (fabric/target
queue) · dispatched-never-completed · quick MISCOMPARE + retries (protocol
amplification) · READ behind many CAWs (ordinary head-of-line) · READ aborted
while outstanding.

Cold-LBA behavior during the storm is the discriminator for the 60 s:
- not dispatched → the **initiator** queue is quiesced;
- dispatched but stalled → target/LUN/fabric-wide head-of-line blocking;
- completing normally → genuine **per-LBA** serialization.

## A/B experiments, in value order

1. Test knob: allow only **ONE outstanding CAW per slot**, everything else
   unchanged. Aborts and 60 s events vanish ⇒ CAS concurrency is causal.
2. Knob that skips **only** the root release-all.
3. Replace teardown CAWs with an **equal-rate READ** workload — controls for
   offered command rate better than the current read-only control.
4. Sharply lower device queue depth.
5. Vary the SCSI command timeout — if the spike tracks it, the 60 s is
   initiator timeout/EH, not target service time.

## Fix order

1. **Observability first** (above).
2. **Operational guardrail**: low per-slot CAW concurrency, batching, bounded
   retries.
3. **Teardown semantic change — the highest-value fix, because it REMOVES work
   rather than scheduling it better.** Membership departure *logically*
   invalidates every grant of the fenced incarnation; stale physical bits never
   block progress; cleanup is lazy and single-owner.
4. **No storage poll on a cached serve** — valid only once the lock cache is
   proven protected by a revocation protocol, a valid fenced lease, a
   membership epoch, or an authoritative grant.
5. **Format redesign**: writer gate + per-node reader records, or a
   partitioned/network DLM.

## Why "just skip release-all" is UNSAFE on its own

> The one thing I would not do is simply "skip release-all because heartbeat is
> gone" while retaining node-ID-only bitmap semantics.

- **Node-ID reuse / ABA.** Old incarnation `node 7 epoch 12` leaves bit 7 set;
  ID 7 is reassigned at epoch 13; the stale bit reads as a live holder — and a
  new node can see its own bit already set and wrongly believe its acquisition
  made a transition. Requires incarnation/epoch **in holder state**, or an
  authoritative per-node incarnation table consulted during lock validation, or
  a guaranteed full purge before ID reuse.
- **Departure ordering.** "Clear heartbeat, then stop" is unsafe: a delayed CAW
  from the departed incarnation can execute *after* peers decide its bits are
  stale. Correct order: mark draining → refuse new acquisitions/promotions →
  drain filesystem ops and all outstanding storage/DLM commands → **resolve
  ambiguous timed-out commands** → establish no old-incarnation command can
  execute (full drain with reliable ordering, or target fencing, or an epoch
  protocol) → publish incarnation inactive → no further I/O.
- **Survivor rule.** Holder of the *currently active* incarnation ⇒ conflicts
  normally. Fenced/inactive node, or an older incarnation ⇒ **logically
  absent**. Physical cleanup optional and never required for forward progress,
  and conditional on the record still being the version inspected.
- **Purge herding.** If N departures make every survivor scan and clear the
  same records, the storm just moves to the survivors. One elected reaper,
  partitioned cleanup, or lazy cleanup.
- **Precondition:** if today's crash recovery *requires* eager physical purge
  before locks can proceed, this is a protocol change, not an unmount
  optimisation. Test first: crash with many holders; crash with an outstanding
  CAW; fenced while an old command is delayed; immediate node-ID reuse; cleaner
  crashes mid-purge; two survivors purging the same holder; old and new
  incarnations overlapping via partition/rejoin.

## The format shape it endorses (gate + per-node reader records)

Per resource: a small **gate/intent record** (state, epoch, writer incarnation)
plus **one reader record per node** at independently writable locations.

- **Reader**: read gate (open at epoch e) → publish its reader record (held
  state, epoch e, node incarnation) → make it durable → **re-read the gate** →
  succeed only if still open at the same epoch, else clear and retry. That
  second read closes the race where a writer closes the gate mid-publish.
- **Writer**: CAS the gate open→closed with a new epoch and writer incarnation
  → no new reader can complete the handshake → scan all reader records → wait
  for live readers to drain or revoke them → ignore/clean fenced or old
  incarnations → enter exclusive. **No coherent snapshot of all reader records
  is needed**, because the gate closed first.
- **Cost**: EX acquire = one serialized gate transition + O(N) reader-record
  reads (bounded parallel batches, do not recreate a queue-depth storm) + drain.
  Shared acquire = two gate reads + one write to the node's OWN record; only the
  0→1 local-reference transition runs the protocol.
- **Crash cases**: reader crash after publish ⇒ ignored only once its
  incarnation is fenced. Writer crash with gate closed ⇒ takeover only after
  fencing, and **bump the epoch to prevent ABA**. Writer crash mid-scan ⇒
  harmless once gate+intent are durable; repeat the scan. Timed-out write ⇒
  ambiguous, re-read and reconcile by epoch.
- **Residual hot spot**: the writer gate is still serialized — acceptable
  because exclusive ownership is intrinsically serialized — but a queued-writer
  protocol or coordinator avoids many EX contenders CAS-looping on it.
- **Do not** pack independently hot records into the same atomic sector, and
  watch for a new aggregate hot spot if all of one node's resources share one
  sector.

## On the current one-sector bitmap

Fundamentally limited for mutation-heavy workloads: every successful update
invalidates all competing comparisons, each loser re-reads and retries, N
simultaneous distinct bit updates approach O(N²) total work, and every unrelated
bit shares the same failure and timeout domain. **No backoff changes the
serialization bound** — it only prevents catastrophic overshoot. Standard
alternatives: network/partitioned DLM, per-node lock/intent records,
leases/delegations, resource mastering, queued locks, sharded summaries (false
positives allowed, false negatives never), hierarchical/subtree grants.

## Standing hazards restated

- **A timed-out or successfully ABORTed CAW may still have been applied.**
  Every retry/recovery path must re-read and reconcile by epoch; never assume
  the write did not happen. A bitmap alone may not carry enough information to
  distinguish "my write landed" from "another writer produced the same image".
- **FUA is not protocol ordering.** It affects device caching semantics; it
  does not create a coherent distributed snapshot and does not fence commands
  from a departed initiator.
- The bounded deadline landed earlier fixes the user-visible upper bound and is
  worth keeping, but **cannot make an overloaded optimistic CAS protocol
  stable** — retries add load exactly when the system needs less.
- D-32NODE-SHARED-DIR-CREATE-PACE is "highly consistent" with one directory
  lock record becoming an EX-transition hot spot; D-READDIR-PEER-CACHED-DIR-PACE
  has several other candidate causes (lock acquisition, coherency invalidation,
  journal recovery/checkpointing, metadata cache miss, repeated verification).
  Trace their CDBs before assuming a shared root.

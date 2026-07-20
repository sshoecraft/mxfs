---
name: AAA-ccloop7251-sess9-GPT-RULING-3fronts-32tcp
description: GPT ruling (RULE 5) on the 3 32/tcp fronts: B=ioend grant-epoch drain state machine (ship first), C=gen-qualified orphan intent, A=master BAST-at-ins…
metadata:
  type: project
tags: [ccloop-72513a13, sess9, gpt-consult, design, tcp]
---

# GPT (gpt-5.6-sol) ruling on the sess9 32/tcp trio — execute in THIS order

## Theme: BAST pending = pressure to relinquish, NOT loss of grant. Ops admitted under the current EX epoch must COMPLETE under it; only NEW admissions stop.

## FRONT B (ship FIRST — direct data loss): extending-write size=0
- Bug: FIX-25 admit-ioend gate treats BAST/DEMOTING as grant-already-stripped; parked
  ioend left native writeback accounting (so sync returned!); drop_caches evict destroyed
  the pending setfilesize → di_size=0 with nx=2 durable.
- Design: grant-epoch drain state machine per inode grant:
  ACTIVE/EX (admit + tag ioends with grant epoch) → QUIESCING on BAST (block NEW
  admissions only) → DRAINING (already-admitted ioends RUN conversion + setfilesize
  UNDER the still-held EX; drain WAITS for: data writeback, unwritten conversion,
  setfilesize tx, log/destage) → only then wire unlock. Admitted ioends get a
  drain-owned authorization token; they never re-check bast_pending like new ops.
- NEVER requeue an ioend after ending page-writeback/native accounting — sync's
  file_write_and_wait must keep covering it (upstream: writeback/ioend lifecycle is
  what sync waits on; there is NO AIL item before the setfilesize tx exists).
- Eviction: secondary safety boundary — evict hook must synchronously quiesce all
  private async state (admitted ioends, release-drain work, DLM callbacks) before
  freeing; I_FREEING with bast_pending/stale + live ioend = assert/quarantine.
- If grant truly stripped before completion: reacquire + validate (ino, GENERATION,
  mapping, no truncate/reuse) before setfilesize; better to prevent via drain-holds-grant.
- Traps: drain-waits-ioend vs ioend-waits-DEMOTING deadlock (grandfather admitted);
  premature page-WB completion; failed conversion/setfilesize must FAIL the drain
  (quarantine grant), never convert to successful unlock; nx=2 doesn't prove
  conversion ran (trace extent STATE).
- Trace chain if needed: ioend alloc → bio complete → queued → gate decision →
  conversion → setfilesize commit → page-WB finish → filemap wait → log force.

## FRONT C (second): AGI unlinked-bucket leak (P2L-INACT-LEAK 2001×)
- Invariant: durable orphan/free intent bound to (ino, GENERATION); incarnation may
  not be REUSED until orphan-removal + ifree commit atomically under a cluster
  LIFETIME lock (GFS2 iopen / OCFS2 orphan-dir semantic).
- Stale actor NEVER acts destructively on a newer-gen inode; demote+reacquire is NOT
  a freshness boundary (cached grants + stale buffers defeat it — likely why P2I
  "fix" fires 2001×: reload reuses stale buffer, or skipped during I_FREEING, or
  disk still holds pre-free image because the PREVIOUS freer's destage was skipped
  = cascading staleness — check which via uncached read of di_gen when diagnosing).
- Gen older than durable intent = destage/visibility invariant failure (loud).
- Inode-number-only AGI chains are ABA-vulnerable: either strictly forbid reuse
  until chain cleanup, or add side orphan structure keyed (ino, gen).
- Lock order to fix: DLM lifetime lock → AGI lock → buffer/inode locks.

## FRONT A (third; removes the 300ms staircase, shrinks B's window): round-open pace
- Most-likely: master defers BAST until waiter becomes grant-eligible (P6-FAIRQ
  queues 'behind waiter' silently). Fairness must order GRANTS, not suppress
  CONFLICT NOTIFICATION.
- Fix: at insertion of ANY incompatible waiter, immediately compare against the
  GRANTED set and send/coalesce BAST to each incompatible holder (per-holder,
  per-grant-epoch 'BAST sent' dedup bit; escalate mode if a later waiter needs
  stronger demotion; clear/rearm only when conflict gone or new epoch).
- Holder: on BAST arrival, arm dwork for REMAINING grace (40ms), not mht window.
- Discriminating trace (if needed): master req-recv→BAST-send / send→recv /
  recv→bast_pending / pending→work-start — 300ms lives in exactly one gap.
- Traps: never clear bast_pending on aborted drain while waiter exists; BASTs can
  be dup/reordered/stale (epoch-associate); no sends under master queue spinlock;
  waiter-behind-waiter still conflicts with HOLDERS; coalesce at 32 nodes; keep
  2-25ms poll as backstop only.

## GPT priority: B → C → A. A is NOT the correctness fix for B.

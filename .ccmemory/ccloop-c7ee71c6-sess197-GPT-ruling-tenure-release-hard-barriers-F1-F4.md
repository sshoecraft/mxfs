---
name: ccloop-c7ee71c6-sess197-GPT-ruling-tenure-release-hard-barriers-F1-F4
description: sess197 RULE-5 ruling: F1/F3/F4 are HARD release-blocking barriers before enforcement gate; F2 needs durable flush + explicit domain knob; 10-step bu…
metadata:
  type: project
---

# sess197 GPT ruling — tenure-release invariant hard barriers (D-FOREIGN-REPLAY item 2)

Full ruling text in sess197 transcript (task koqgeh7mr). Line-cited audit that
fed it is in .ccloop/handoff.md sess197 + ccmemory sess196 entries.

## Unified release predicate (the invariant, final form)
"A resource may become peer-claimable only after local mutation quiesced,
every home-write obligation of the retiring tenure completed, the required
persistence barrier covers those completions, and an immediate pre-CAS
recheck shows none of those facts changed." Peer-claimable = handoff-arm CAS
AND free-slot release (waiter can self-claim).

## Dispositions
- F1 (ICLUS make_durable 250ms "releasing anyway", xfs_mxfs_dlm.c:44741):
  HARD. Never unlock on timeout. Deferred-release state machine: DEMOTING →
  block admissions → retain grant → ordinary worker (NOT bast_notify/
  release_check ctx) drives log/AIL/writeback via lock-order-safe paths →
  retry proof → unlock only on proven predicate; bounded no-progress →
  wedge/shutdown. Initial BAST arms a SELF-RESCHEDULING drain worker (never
  depend on BAST redelivery). REJECTED: release-then-block-waiter's-gate
  (obligation would outlive a dead releaser).
- F2 (fua_disable=1 no real flush at tenure boundary): HARD whenever target
  power loss in scope. "Single shared target" reasoning UNSOUND — volatile
  cache loss persists arbitrary subsets (CAS may survive while home write
  lost, etc.). Required: mxfs_blkdev_flush_durable after last home
  completion BEFORE any peer-claimable CAS, for ALL classes (AG too, not
  just inode/ICLUS); skip only if tenure provably created zero obligations;
  flush tickets coalescable device-wide. ALSO: newly minted epoch must be
  durable before new tenure's first durable tagged record (both handoff and
  self-claim mint). Two supported modes: (1) crash-durable gate mode;
  (2) volatile-target/coherence-only mode — flush_epoch no-op OK but gate
  enable REFUSED unless domain explicitly selected via a SEPARATE knob
  (never overload mxfs_fua_disable).
- F3 (FUA-mode check-to-CAS window): HARD. Proof must be completion-driven:
  quiesce → drain all (incl ICLUS) → verify zero obligations+inflight →
  capture dirty_seq → issue/join flush → on completion recheck dirty_seq/
  obligations/inflight/pins unchanged → final tripwire pre-CAS. relbar fast
  path may skip flush ONLY with a flush ticket covering the final completion
  set. P3B must count ICLUS/home metadata completions, not only dir bios.
- F4 (dir committed-never-submitted): HARD. Fork walks + inflight counts
  insufficient. Per-tenure obligation registry: create obligation when a
  buffer mod becomes committed to the retiring tenure (once per dirty
  generation, NOT per xfs_trans_log_buf), retire only when home iodone
  covers the LATEST committed generation (relog while in-flight must not
  retire the newer obligation); cancel on trans abort. Start with dir
  data/leaf, then make it THE common accounting for all gate classes.

## Instrumentation (step 2)
Per-resource state: tenure_epoch, release_state (ACTIVE/DEMOTING/DRAINING/
PROVED/RELEASING/WEDGED), dirty_seq, obligations_outstanding (+optional per
class), home_io_inflight, flush_ticket required/completed, admission_seq.
One RELEASE CERTIFICATE trace record per release attempt (not per buffer):
epochs, path, dirty_seq at quiesce/flush-issue/tripwire, obligations at
quiesce/flush-issue/CAS, inflight at CAS, ticket status, CAS result,
handoff-vs-free, durations, defer/wedge reason. Aggregate counters incl.
"CAS attempted with invalid proof" — must SUPPRESS the CAS + wedge, not
just count. Shadow checker (default-off audit builds) compares CIL/AIL/
buffer/fork scan vs registry at release time — discovery tool only.

## Fault injection: 18 stable stage IDs (see transcript) keyed on
resource/epoch match; special injectors: ICLUS destage in both windows, dir
relog over in-flight bio, CIL-resident unsubmitted dir buf, release
timeout, CAS fail/retry, waiter self-claim. F2 needs TARGET-CACHE-LOSS
tests (discard acked-unflushed writes, reboot from stable image) — node
kills do NOT cover it. Ground-truth oracle: per tagged image record
payload hash/class/resource/epoch/commit/submit/stable points; assert
accepted↔lineage-valid, rejected-stale↔home-newer, sole-surviving-copy
never rejected, new-tenure image never stable before its epoch mint.

## Build order (gate stays DISABLED throughout 1-8)
1. Gate-enable prerequisites fail closed (unsupported config refuses).
2. Release certificates + counters + fault hooks (static keys, default off).
3. Common release-proof helper/state machine; convert paths incrementally.
4. F4 obligation registry (dir first; relog+abort tests; shadow census).
5. F3: ICLUS into common accounting; kill relbar fast path unless ticketed.
6. F1: deferred worker retry + bounded wedge; stress lock order first.
7. F2 crash-durable mode (flush all peer-claimable releases w/ obligations;
   epoch-mint durability both sides; teardown refuses clean if flush fails).
8. Boundary crash boards, gate in AUDIT mode (compute would-accept/reject
   vs stable-media oracle).
9. Enable per class: AG → inode → ICLUS → dir. Boards per step.
10. Global enable only at zero invalid certificates + zero oracle mismatch.
RULE-0: one deterministic stage per node/seed, rotate stages across 32
nodes; full cache-loss matrix only on dedicated crash boards.

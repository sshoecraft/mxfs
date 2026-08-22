---
name: ccloop-c7ee71c6-sess231-GPT-ruling-a2-ifree-shape-and-finobt-triage
description: sess231 RULE-5 ruling: a2 first (split-phase ifree, ZERO wait under ILOCK); detector progress-aware separately; finobt-481 triage = containment audit…
metadata:
  type: project
---

# sess231 RULE-5 ruling — a2 implementation shape + FINOBT-481 triage (gpt-5.6-sol)

Context: incident481 confirmed the cross-node ILOCK-over-CAW-poll convoy (12 nodes,
kworker/inodegc). Post-recovery chk_mxfs found on-platter finobt/inobt divergence
(2 AGs, +4 delta each, AGI agrees with finobt) + 10 leaked nlink=0 orphans.

## Q1 — a2 for xfs_inactive/xfs_ifree: shape (iii) AMENDED
- Land a2 FIRST (fleet-stability fix). Rule must become mechanically enforceable:
  "No potentially sleeping remote DLM op / CAW request / grant poll while ANY inode
  ILOCK is held."
- NOT option (i) (hidden unlock in AG hook — no context, breaks lockdep/callers).
- NOT option (ii) (unconditional AG-before-ILOCK for every inactivation — only ifree
  phase needs the AG, would serialize unrelated inactivations).
- Shape: split-phase (iii) but NO bounded wait under ILOCK: under ILOCK only
  (a) use already-valid local AG tenure, or (b) genuinely zero-wait try that cannot
  issue/wait SCSI. On miss: drop ILOCK immediately, acquire AG tenure, relock,
  revalidate, restart the ifree txn. If the "nonblocking" CAW try can submit SCSI
  synchronously, it is NOT nonblocking enough for under-ILOCK use.
- No txn allocated/joined across the drop. Never a backout-unlock that bypasses
  drain pipeline. Retaining AG tenure across local retry preferred over release/
  reacquire churn.
- Revalidation set after relock (implement as single xfs_ifree_revalidate()):
  identity (ino+generation+not-reclaim), authority (AUTH_EX_OPEN, epoch==E, pin
  valid, no CLOSING/fence/recovery), eligibility (nlink==0, still allocated, mode,
  no new data/COW/attr work), unlinked-list state recomputed (discard cached
  predecessor/bucket), AG tenure current (correct AG, gen current, grant-time
  invalidation done), txn state fresh (no pre-drop bufs/cursors/mappings).
- Lock-order: after wait, effective order is AG→ILOCK; safe only if ALL remaining
  ILOCK→AG paths are zero-wait/backout. Audit before enabling broadly. Also audit
  inode-authority-EX vs AG-tenure order; a1 pin retains established authority epoch
  through the sequence.

## Q2 — wedge detector: still required, SEPARATE defect from a2
a2 removes the convoy but not legitimate long waits (fenced holder, victim replay,
purge, storage retry, defined recovery transitions). Prior capture proves 8x2s can
shoot bounded recovery. Replace fixed patience with state/progress-aware deadline:
inputs = holder live/fenced/under-recovery, recovery phase+gen changes, replay/purge
progress counters, grant gen/holder changes, AIL-min movement, drain-count movement,
storage retry state. Extend while recognized dependency progresses, under a
documented upper bound + escalation that names the blocking holder (NOT mass
waiter self-withdraw). Drain-before-unlock invariant untouched.

## Q3 — FINOBT-481 triage (A=stale replay clobber, B=authority race, C=asymmetric
containment skip; plus 4th: sequential tenures + stale cached buffer, missing
grant-time invalidation — looks race-like on disk with serialized DLM history)
Investigation order (fastest discrimination):
1. AUDIT CONTAINMENT BRANCH SEMANTICS in source: exactly which txn items survive
   each skip path. AGI+finobt-ahead-of-inobt is EXACTLY what a skip-inobt-only
   containment produces. If skip drops whole txn → cannot produce this; if skips
   finobt only → opposite mismatch.
2. Correlate the 4 differing bits per chunk with skip probes (4 skip decisions per
   chunk → C confirmed/demoted fast).
3. Txn completeness across all slices for the affected physical blocks (AGI, inobt,
   finobt blocks): all-three-logged-then-inobt-regressed → A; inobt absent from
   committing txn → C; multiple coherent conflicting node txns → B/stale-cache.
4. Overlay AG DLM tenure intervals (overlap? invalid-epoch use? sequential
   stale-buffer use?).
5. Replay traces + block-image hashes: final bad inobt image exactly matching an
   older journal image = strongest proof of A.
- +4 repeated in two AGs: favors deterministic unit (4 skip decisions / 4-ino
  workload batch / image lagging one 4-free batch), weakly disfavors free race.
- Orphans: reconstruct nlink→0 txn, bucket insert, list removal, ifree attempt,
  containment skip; orphans in affected chunks/probes → C or stale replay; complete
  unlink-add txn then regressed AGI/list → A.

## Landing priority (verbatim)
1. Emergency a2 for xfs_inactive/xfs_ifree (zero wait under ILOCK).
2. Audit+enforce a2 across all remote-AG paths.
3. Recovery-aware noino-fence detector.
4. Disable or make ATOMIC any asymmetric double-free containment IMMEDIATELY.
5. Correct cross-slice replay ordering before trusting foreign buffer-image replay.
6. Continue a1; relock path validates authority epoch; a3 unchanged.

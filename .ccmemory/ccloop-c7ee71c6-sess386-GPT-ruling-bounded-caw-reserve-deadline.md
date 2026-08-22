---
name: ccloop-c7ee71c6-sess386-GPT-ruling-bounded-caw-reserve-deadline
description: sess386 RULE-5 ruling: land the bounded CAW reserve acquire NOW (deadline+linearizable cancel, grant-wins rule); a1/a2 still required; full A/B evide…
metadata:
  type: project
---

## Context

sess386 measured all four legs of the 474 collapse on one node in one incident
(evidence: /src/mxfs/.evidence/sess386_ailfreeze_1313 + /tmp/run_rsync_paired_20260821T132405Z):

- LEG A: create holds AGI in txn, blocked in caw_wait_for_grant for MINUTES via
  mxfs_dialloc_reserve_ino -> mxfs_v5_dlm_inode_lock_retries. THE HOLE: the
  retries bound is TCP-only; the CAW branch (dlm/v5_mount.c:5829) comments
  "CAW: no short-budget variant" and does a full-budget blocking acquire.
- LEG B: ino-BAST kworker holds ILOCK(1035) in xfs_inactive_ifree, blocked on
  the same AGI buffer (P-BUFLOCK-STUCK daddr=2 ops=xfs_agi).
- LEG C: AIL min = ino 1035 INODE item; 2247x P129-CLSKIP ILOCK_NOWAIT_FAIL.
- LEG D: mxfs_noino_drain_fence frozen 8 pushes -> P-NOINO-RELFENCE-WEDGE ->
  shutdown -> cascade (13-14 nodes, 3 incidents).

## Ruling (gpt-5.6-sol, sess386)

1. **Land the bounded CAW reserve fix first** — it restores the already-approved
   ccloop-4dd7 design contract and is attributable in A/B. It is containment,
   NOT the full fix: a1 (authority-epoch at BAST release) and a2 (no blocking
   remote acquire under ILOCK/AGI/buffers, skipped!=drained visible) remain
   required; dirty-fallback and xfs_bmap_btalloc-type sites remain open.
2. **Cancellation must be linearizable**: request identity, WAITING->CANCELLED
   vs WAITING->GRANTED compete via CAW on the exact value; **grant wins ->
   return success and USE the lock** (never receive-then-release at deadline —
   that release path enters the drain fence). Never return -EAGAIN on uncertain
   state (transport error -> recovery, not -EAGAIN).
3. Deadline = absolute monotonic, set BEFORE waiter registration, covering
   registration + poll + cancel confirmation. Default 500ms-1s; cap at
   fence_budget/16..8; floor above storage tail latency. Report overshoot.
4. -EAGAIN path: salted/permuted per-node AG order, rotate candidate cluster,
   short per-cluster contention cooldown, randomized backoff OUTSIDE the AGI
   hold, escalating after full failed sweeps. NEVER convert contention to
   ENOSPC — bounded sweeps + jitter + retry; the eventual starvation escape is
   drop-AGI-acquire-relock-revalidate (a2 form), NOT an ad hoc unbounded wait.
5. A/B evidence: the causal chain must be shown unwinding (deadline/cancel ->
   AGI unlock -> ifree completes -> ILOCK free -> AIL-min advances -> fence
   drains); plus grant/cancel race fault injection (8 orderings listed in the
   full reply), slot scans for phantom waiters/orphan grants, dirty-fallback
   counter treated as release blocker if frequent.

Full reply in the sess386 transcript. Fix target: mxfs_v5_dlm_inode_lock_retries
CAW branch + caw deadline variant + dialloc -EAGAIN handling audit.

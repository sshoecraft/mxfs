---
name: ccloop-c7ee71c6-sess32-ilock-try-preempt-bypass-admission-hole
description: ADMISSION HOLE FOUND: mxfs_dlm_ilock_try returns true on preempt_count()>0 — atomic trylocks bypass DLM entirely (no DEMOTING gate, no holder count).…
metadata:
  type: project
---

# sess32 — the admission bypass: ilock_try's preempt_count() arm

## The finding (xfs_mxfs_dlm.c ~28290, read-only audit)
Admission during a release IS structurally closed at both entry points —
`mxfs_dlm_ilock_begin` diverts to the DEMOTING wait (fast path checked
before it; state stays DEMOTING through the unlock tail, cleared only at
pipeline exit), and `mxfs_dlm_ilock_try` refuses DEMOTING and i_dlm_stale —
EXCEPT this arm, which precedes every state check:

    /* DLM lock acquire does CAW disk I/O which can sleep.  If we're in
     * atomic context (e.g., xfs_iget holds pag_ici_lock), skip the DLM —
     * local locks provide sufficient protection. */
    if (preempt_count() > 0)
        return true;

An atomic-context `xfs_ilock_nowait` succeeds with NO DLM state consulted:
not counted as a holder (P15 holders-check blind), not blocked by DEMOTING
(admission open mid-release), no tenure/authority at all. "Local locks
sufficient" is only true for READS; a path that acquires this way and later
LOGS the inode commits pend++ invisible to the pipeline — the precise
candidate for the measured flush→unlock recommit window (P228 defers,
119/227k, hot shared dirs) — and in the general case is an uncoordinated
writer while a peer may hold the grant.

## RULE 4 next step (session 15): PROBE BEFORE PATCHING
1. In the preempt arm: counter + capped print
   {comm, _RET_IP_/caller, mode (EX/PR!), ino, i_dlm_state at bypass} —
   `P229-ILOCK-TRY-ATOMIC-BYPASS`. Key question: do EX bypasses happen at
   all, and does any bypassed inode get LOGGED before the matching iunlock
   (pair with a flag set at bypass, checked+cleared in xfs_trans_log_inode /
   ilock_end).
2. If EX-bypass-then-log is measured: the fix is NOT to sleep in atomic
   context — it is to REFUSE (return false) for EX/write requests in atomic
   context (callers of ilock_nowait handle failure by design; they fall back
   to blocking xfs_ilock in process context, which takes the full DLM path).
   PR/read bypasses may stay (local locks genuinely suffice for reads of
   state we hold cached) — decide on the measurement + a GPT consult
   (RULE 5) before changing behavior.
3. Re-measure P228 defers + P220 obligations after: if the recommit window
   closes, the hot-dir defer loop should collapse without any rwsem barrier.

## Cross-refs
- Barrier lesson: never a reader-blocking write wait on a hot dir
  (ccloop-c7ee71c6-sess32-282-283-barrier-convoy-lesson-and-incident).
- Full interlock design + hazards:
  ccloop-c7ee71c6-sess32-admission-interlock-design-ilock-barrier.

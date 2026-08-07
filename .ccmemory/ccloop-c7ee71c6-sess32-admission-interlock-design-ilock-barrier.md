---
name: ccloop-c7ee71c6-sess32-admission-interlock-design-ilock-barrier
description: Interlock design for the 119-defer hot-dir shape: dir admissions ALREADY blocked during DEMOTING; the window is the last admitted ILOCK holder commit…
metadata:
  type: project
---

# sess32 — admission-interlock design grounding (implement in session 15)

## What already exists (read at xfs_mxfs_dlm.c ~6070 comment)
During a release (i_dlm_state DEMOTING/BAST), **new local dir ops are ALREADY
diverted to the slow-path DEMOTING wait** (mxfs_dlm_ilock_begin dir gate:
state != CACHED) — the dir is quiescing by design, and
mxfs_inode_cluster_durable's release-side loop waits (bounded ~3s, 1500
iters) for the inode to leave the AIL, log_force only when pinned.

## Why 119 defers still happen on the hot dir (ino=131)
Each pipeline: queued ops block on DEMOTING → in-flight admitted holder(s)
finish → P15 holders-check passes → durable flush runs → the LAST admitted
op's commit lands (pend++ at xfs_trans_log_inode) AFTER the flush pass but
before the wire unlock → enforce helper's 2 passes run while that op is
between trans_log and commit-complete (nothing force-able yet) → cannot
close (closed=3/122) → defer → pipeline exits (state NONE) → queued ops rush
in → next BAST repeats. Safe but non-convergent per-cycle.

## The convergent fix (small, precise)
In `mxfs_relbar_close_or_defer()`: when the first durable pass leaves the
ledger open, insert a **local ILOCK barrier** before the second pass:
`down_write(&ip->i_lock); up_write(&ip->i_lock);` — the RAW rwsem, NOT
xfs_ilock (which would re-enter mxfs_dlm_ilock_begin → DLM acquire from
inside the pipeline = recursion/deadlock hazard). An admitted op holds
ILOCK_EXCL through commit end, so acquiring the raw rwsem guarantees every
previously-admitted mutator has finished its commit; the DEMOTING gate keeps
NEW ones out. Then the second durable pass (log_force SYNC + iflush + bwrite
+ flush inside mxfs_inode_cluster_durable) captures the final state and the
ledger closes. Expected outcome: deferred → ~0, closed → ~all, same walls.
Hazards to check: (a) i_lock nesting vs the bast worker's own locks at that
point (it holds NO spinlocks at the anchored tail — the unlock does wire
I/O; verify for noanchor too); (b) writers blocked on DEMOTING do NOT hold
i_lock while waiting (verify the wait in ilock_begin sleeps BEFORE
down_write — else the barrier deadlocks against a waiter); (c) bounded —
rwsem wait is bounded by the admitted op's commit, itself bounded.
A/B: same knob (relbar_enforce), compare closed/deferred + hot-dir defer
recurrence + walls.

## Then (per GPT rollout): dir-DATA per-tenure buffer obligations,
orphan/inodegc reacquire class, EX gate, C-full token protocol.

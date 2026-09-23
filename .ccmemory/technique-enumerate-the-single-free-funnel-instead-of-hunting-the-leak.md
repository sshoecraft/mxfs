---
name: technique-enumerate-the-single-free-funnel-instead-of-hunting-the-leak
description: TECHNIQUE (sess565, D-0924): a leak that will not reproduce is bounded by proving the free funnel has one caller, then checking each of its call site…
metadata:
  type: project
tags: [technique, d0924, audit, xfs_buf_item, rule4]
---

# When a leak will not reproduce, audit the funnel instead of running laps

D-0924 (xfs_bufs left in the `mxfs_buf` slab at module unload) had accumulated
**11+ clean laps** across several sessions and would not recur. The record itself
had reached the right conclusion: more clean unloads cannot close it, because
the leaking builds had none of the instrumentation and "builds with probes did
not leak" is the whole of the observation.

What worked instead was bounding the search space by construction.

## The move

1. **Prove the funnel is singular.** `grep` for the deallocator, not the symptom:
   `xfs_buf_item_free` has exactly ONE caller in the tree,
   `xfs_buf_item_relse` (`pal/linux/xfs_buf_item.c:194`). That single fact turns
   "somewhere a reference leaks" into "one of N call sites", where N is small
   and enumerable.
2. **Enumerate the call sites and check each against the invariant.** Four here,
   distinguished since 0.75.95 by a `why` tag the caller passes in:
   - `iodone` — the completion that consumes the token is the very next call.
   - `stale` — an explicit reclaim already ran upstream of the funnel.
   - `release-clean` — **covered by construction**: the tracking is installed only
     from `xfs_trans_log_buf`, which dirties, so an item that was never dirty was
     never tracked. This is the strongest kind of coverage — it needs no code to
     enforce it.
   - `put` — **nothing returns the hold.** The hole.
3. **Gap-check the enumeration against paths the docs call out separately.**
   `xfs_buf_item_unpin`'s stale branch and remove branch *look* like independent
   no-ioend detaches, and the subsystem doc flags them as such. They are not
   separate free routes: stale goes through `xfs_buf_item_finish_stale`, remove
   through `xfs_buf_ioend_fail_unsubmitted` → ioend → iodone. Both already in the
   four.

## Why the laps could never have found it

The `put` route frees a DIRTY item that is not in the AIL, which upstream permits
only with `XFS_LI_ABORTED` set — set in exactly two places, both shutdown paths.
**Every lap ever run against the record was a healthy mount.** The audit doesn't
just find the hole, it explains the eleven clean laps, which is what makes it a
disposition rather than another guess.

Confirmed rather than assumed: three laps on 0.75.95 fired the caller-aware probe
**zero** times, exactly as the code says must happen on a healthy mount.

## Two traps this leaves behind

- **An `ASSERT` is not a guard.** `xfs_buf_item_put`'s `ASSERT(!dirty || ABORTED)`
  documents the constraint and is compiled out in this build (no DEBUG/XFS_WARN).
  Reading it as enforcement inverts the conclusion.
- **Reproducing the route needs concurrency, not just a shutdown.** The window
  wants a buffer logged and committed by transaction T1, a checkpoint that aborts
  it, and a *different* transaction holding a clean reference that drops it via
  `xfs_trans_brelse` — brelse early-returns on `XFS_LI_DIRTY`, so the transaction
  that logged the buffer can never be the one that puts it. A single-threaded
  loop cannot produce it (measured: `tests/agmeta_shutdown_retire.sh` s596a shut
  the fs down cleanly and still scored `put_probe=0`).

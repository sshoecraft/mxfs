---
name: sess-tcp-dlmfairness-residual-is-stale-readdir-selfheal
description: dlm_fairness residual is a RARE TRANSIENT stale-readdir (got=1 self-heals to 0; dir actually empty). 3/3 standalone PASS. Fix = readdir-time dir-bloc…
metadata:
  type: project
---

## Refinement of the last 2/tcp blocker (build F22321)
After the full-suite re-run FAIL `df shared dir drained got=1`, I ran dlm_fairness standalone
3x: ALL PASS (19.2/13.1/12.9s), and post-run `ls /mnt/shared/.dlm_fairness` = 0 files on BOTH
nodes. So the dir IS actually empty — the `got=1` was a TRANSIENT STALE READDIR at the
drain-check instant that self-heals on a later read. It is NOT a durable lost/leaked dirent.

=> The last residual making the 2/tcp suite not-100%-reliable is a RARE readdir-time dir-block
coherency staleness: rank1's `ls` momentarily reads a pinned/gen-stale dir DATA block (the
long-standing DIR-STALE-SKIP pin=1 family) showing a dirent a peer already removed. Low rate
(passed full-suite run1, failed run2, 3/3 standalone).

## FIX DIRECTION (next session, to reach reliable 100%)
Make a READDIR (not just modifying ops) refresh a stale cached dir DATA block. Today
xfs_da_read_buf (xfs/libxfs/xfs_da_btree.c ~L3153) only invalidates+re-reads a gen-stale block
when it is NOT pinned/dirty/in-AIL; a pinned gen-stale block hits the DIR-STALE-SKIP else-branch
and is served stale. For a non-modifying readdir there is nothing of ours to lose, so a pinned
stale block COULD be force-unpinned (xfs_log_force) + re-read, or the dir-EX acquire for the
read should drain+refresh. Tie-in: harden dlm_fairness margins by also lowering
MXFS_LOCK_ACQUIRE_WAIT_MS 6000->~2000 (50-round churn accumulates 6s lost-grant recoveries).
Verify: run ./run.sh 2 tcp dlm_fairness ~10x with 0 FAIL.

## OVERALL session result: 4 FAIL -> 5/6 coherency tests RELIABLE + dlm_fairness rare-flake;
8 PENDING stubs remain. Criterion (100%) NOT yet met. Marker NOT written. See
[[sess-tcp-FIX-etimedout-retry-posix-multi-PASS]], [[sess-tcp-MILESTONE-full-suite-8pass-0fail]],
[[sess-tcp-STATE-5of6-reliable-dlmfairness-residual]].
</body>

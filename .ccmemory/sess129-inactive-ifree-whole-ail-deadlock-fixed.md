---
name: sess129-inactive-ifree-whole-ail-deadlock-fixed
description: sess129 FIX (build 3D8C9779, KEEP): posix_semantics(1) PASS. test_many_files wedge = xfs_inactive_ifree whole-AIL push vs creator holding dp ILOCK_EX…
metadata:
  type: project
---

# sess129 — single-node test_many_files AIL wedge ROOT-CAUSED + FIXED

## Root cause (RULE 4, fully instrumented chain)
Probe build `C6E5ECF0` (P129-IPUSH / P129-CLSKIP gated on `mxfs_ailstuck_probe`
latch set by the P128-AILSTUCK dump) proved:
- Stuck AIL head inode item (ino 6291584 = the `many_files` TESTDIR dp) never flushes
  because `xfs_iflush_cluster` hits `ILOCK_NOWAIT_FAIL count=1 owner=bash pid 995`
  → `-EAGAIN` → push returns LOCKED forever.
- `sched_show_task(owner)`: bash sleeps in `schedule_timeout_uninterruptible` inside
  `xfs_iget` ← `xfs_icreate` ← `xfs_create` — the iget -EAGAIN delay(1) retry loop.

**ABBA cycle:** test recreates 250 just-deleted files. `xfs_create` re-takes
dp ILOCK_EXCL after `xfs_dialloc` (v0.3.148 design) and holds it across
`xfs_icreate→xfs_iget`. The dialloc'd ino's prior incarnation is NEED_INACTIVE
in cache → iget `out_inodegc_flush` → -EAGAIN loop (holding dp ILOCK_EXCL).
inodegc workers sat in MXFS's post-commit durability block in
`xfs_inactive_ifree` doing `xfs_ail_push_all_sync` = wait for the WHOLE AIL,
which contains dp's dirty item, whose flush needs dp ILOCK_SHARED → deadlock.
(Upstream never waits for the whole AIL there; the "per-inode and bounded so
the heavy push is safe" comment was refuted.)

## Fix (build `3D8C9779F4260B7DA560E45`, KEEP)
`xfs/xfs_inode.c xfs_inactive_ifree`: replace `xfs_ail_push_all_sync(mp->m_ail)`
with settle (log_force SYNC + msleep(10) + log_force SYNC) +
`mxfs_ail_drain_inode_sync(ip)` (sess109 helper, un-static'd, declared in
xfs_mxfs_dlm.h) — waits ONLY for ip's own item to leave the AIL; ip's ILOCK is
free there (released at trans_commit) so it always progresses. AG-meta
durability for peer handoff stays with the Phase-2 BAST drain (invariant #1).
Kept xfs_buftarg_wait + blkdev_issue_flush.
Result: test_many_files 13s PASS (was infinite wedge + virsh destroy needed).

## Second bug: run_tests.sh rc=2 with all tests PASS
Under `set -euo pipefail`, `timing_files=$(ls "$TIMING_DIR"/*.csv 2>/dev/null | wc -l)`
aborts the script with rc=2 when no CSVs exist (ls glob-fail rc=2 + pipefail),
AFTER the summary prints → criterion saw `passed=12 failed=0 rc=2` = FAIL.
Fixed with `find -name '*.csv' | wc -l`. Watch for the same ls-glob pattern in
other harness scripts.

## Probes left in tree (zero-cost until a wedge)
- `mxfs_ailstuck_probe` atomic (xfs_trans_priv.h/xfs_trans_ail.c), latched by
  P128-AILSTUCK after ~30s of stuck `xfs_ail_push_all_sync` wait.
- P129-IPUSH branch logs in xfs_inode_item_push; P129-CLSKIP skip-reason logs
  (incl. rwsem owner comm/pid + sched_show_task ×3) in xfs_iflush_cluster.

## Infra notes
- After any manual virsh power-cycle, `/mnt/mxfs-src` NFS is NOT mounted →
  tests fail "No such file or directory". Criteria `fresh_cluster_mount` fixes it.
- posix_semantics(1): `RESULT: PASS passed=12 failed=0` with this build.

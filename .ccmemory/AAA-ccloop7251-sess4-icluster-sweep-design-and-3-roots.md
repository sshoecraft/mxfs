---
name: AAA-ccloop7251-sess4-icluster-sweep-design-and-3-roots
description: sess4: iclus REWORKED to coverage-sweep (no refcounts); 3 proven roots fixed: dir-in-cluster sweep livelock, inactive-guard 2-resource deadlock, evic…
metadata:
  type: project
---

# sess4 (ccloop 72513a13) — ICLUSTER Phase 1 live at 8/cawd

Build lineage: 0.11.16, srcversion at last good build `047CF55FA6EA3BB1EC864A4` (knob `MXFS_EXTRA_MODARGS="icluster_dlm=1"`).

## Core design change: coverage-sweep, NOT refcounts
Session-start audit found per-grant refcounts (ex_refs/pr_refs) structurally fragile:
PR→EX upgrade is lock-lock-unlock (2 counts 1 drop), ilock_try counted one-sided,
walker-1 popped before locking, and ~6 recovery paths set i_dlm_mode=NL without a
release call (P72 orphan, P106 bail, teardown, single→multi wipe). Any imbalance
leaks (cluster never releases) or steals (releases under a live sibling → split
brain). REWORK: release decision = sweep of covered in-core inodes
(mxfs_iclus_covered_active: INCORE iget, i_dlm_mode!=NL || i_dlm_acq_inflight,
ROUTED inodes only). ic->busy serializes acquire vs release sweep; admit windows
covered by acq_inflight brackets (ilock_begin existing; ilock_try new bracket).
EDEADLK from v5 upgrade → ic->bast_pending=true (self-BAST) → existing demote
pipeline drains+releases+reacquires.

## Three PROVEN roots fixed during bring-up (all RULE-4 evidence-driven)
1. **Sweep counted unrouted inodes** → dir 131 + root dir live in cluster base
   128 with routed files; dir's ever-present per-inode EX kept sweep dirty →
   rm's upgrade EDEADLK livelocked 65 laps → FS shutdown (test1). Fix: sweep +
   fan-out filter mxfs_iclus_routed(ip).
2. **xfs_inactive double-free guard = 2-resource deadlock**: guard takes RAW
   per-inode EX then needs cluster EX inside truncate/ifree; peer retains
   cluster and can't release (its own in-core copy of same ino awaits the same
   guard) → 270s+ P-WAIT-EXTEND wedge. Fix: guard routes through
   mxfs_iclus_lock/unlock(is_free=true) when mxfs_dlm_iclus_covered(ip)
   (exported wrapper); EDEADLK retry now a 3-lap loop (xfs_inode.c).
3. **Evicted-dirty-dinode stale read (zero_silent_loss root)**: writer's file
   evicted before any BAST → size update only in LOG → platter dinode size=0 →
   sweep clean → cluster released with NO drain → readers read 0 bytes
   (RELOAD-SIZE-DROP-SKIP mem=262144 disk=0 on node5; per-inode slot MIRROR
   used to mask this; iclus has no mirror). Fix: mxfs_iclus_make_durable(mp,
   base) before EVERY cluster disk release (log_force SYNC + cluster-buffer
   settle loop, alloc-buflist-aware per sess115 pattern + blkdev_flush_epoch).

## Also routed/gated this session
ilock_try slow path (try_admit + acq_inflight bracket), teardown unlock skip,
P72 orphan device-scan skip, ioend-admit g2 + reload sc_grant_held redirect to
mxfs_iclus_granted_mode, iget visibility nudge cluster PR nudge. Dir-probes in
xfs_buf.c/dir2_data.c are dir-only → untouched. P108/P106/dir-EX verifies are
S_ISDIR-gated → untouched.

## Status at save
- PASS knob=1 @8/cawd: dir_reuse (124s calibrate), cache_coherency (13-21s),
  posix_multi (10s), zero_silent_loss (4s, was 1/8 before make_durable).
- dir_reuse over 120s enforced budget (~140s): per-round ~20s = create 3-7s
  (dir-EX rotation, P138 dir BAST=56ms each) + verify 4-10s (≈11ms/file cold:
  per-inode reload-on-acquire FUA read fires per FILE though cluster grant
  unchanged — NEXT LEVER: skip reload when ic grant_seq unchanged since last
  load of that inode) + rm-barrier 6s (rank1-only rm -rf 800 + slowest-verify
  skew). 163 iclus EDEADLK/run benign. P2I-INACT-UPG=0.
- Remaining battery: mmap_coherency, crash_consistency @8. Then Phase-2 perf
  (reload-skip, allocation steering, MHT/dir batching), AG admission fix,
  4-condition 32 ladders.

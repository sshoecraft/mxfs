---
name: sess-tcp-dir-lostupdate-is-multiblock
description: NARROWED: concurrent-dir lost-update only at MULTI-BLOCK dir volume. 10 files/node concurrent → both see 20 (CONVERGES, P62-RELOAD shortform→block).…
metadata:
  type: project
---

## NARROWED ROOT (build B77AD901) — refines [[sess-tcp-posix-multi-concurrent-dir-visibility-gap]]
Concurrent same-dir insert convergence is VOLUME-dependent:
- 10 files/node concurrent (both nodes, barrier, count) → BOTH see 20. CONVERGES. dmesg
  shows `P62-RELOAD-FORK-SHRINK ino=... incore_fmt=1 disk_fmt=2 ... disk_size=4096` (dir
  reloaded, shortform fmt=1 → block fmt=2). So reload-on-acquire works for small dirs.
- 100 files/node → each node persistently sees ONLY its own 100 (durable lost-update,
  proven stable across repeated reads minutes later).
=> The lost-update is specific to MULTI-BLOCK (block/leaf-format) directories. The dir
reload-on-EX-acquire and/or drain-on-release covers shortform + the first/single data
block, but NOT all data blocks once the dir spans multiple 4K dir-data blocks. Node B's
EX-acquire reload doesn't pull in node A's inserts that live in dir data blocks beyond what
the refresh reloads → B builds its 100 onto a base missing A's → commits → durable divergence.

## CANDIDATE FIX SITE
- `mxfs_dlm_dir_modify_refresh(dp)` — xfs/xfs_mxfs_dlm.c:1981 (called at create EX-acquire
  xfs_inode.c:1355, and rename/remove 3420/3807/3809). READ IT: does it invalidate/re-read
  ALL of dp's dir DATA blocks (xfs_da_read_buf gen path for every block) or just the dinode
  fork / block 0? The fix is almost certainly: make it bump i_dlm_dir_gen so EVERY dir data
  block re-reads (the xfs_da_read_buf b_mxfs_dir_gen<i_dlm_dir_gen invalidation, v0.4.7),
  AND ensure the release path drains EVERY dir data block durable (mxfs_dir_data_durable /
  mxfs_dir_push_data_ags) not just block 0.
- Mirror the proven small-dir reload to the multi-block case.

## REPRO (fast, reliable)
`./run.sh 2 tcp posix_multi` OR minimal: both nodes create N files in one fresh dir +
coord_barrier + count. N=10 converges (20), N=100 diverges (100). Binary-search N to find
the multi-block threshold (~dir exceeding one 4K data block, roughly >~50-60 short names).
Instrument mxfs_dlm_dir_modify_refresh + xfs_da_read_buf to log per-block gen at the EX
acquire that ends up missing the peer's entries.

## Session end state
5 code fixes KEEP (B77AD901). 6 multi-node suite tests wired+working
([[sess-tcp-suite-port-multinode-tests]]); strong_consistency + zero_silent_loss reliably
PASS 2/2; cache_coherency/posix_multi/mmap/dlm_fairness fail on this dir lost-update +
intermittent barrier desync. Criterion NOT met. This multi-block dir lost-update is the
next fix; then re-run all 6 + finish porting fault/perf tests.
</body>

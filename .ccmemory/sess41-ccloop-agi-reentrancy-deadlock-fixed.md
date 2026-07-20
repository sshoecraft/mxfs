---
name: sess41-ccloop-agi-reentrancy-deadlock-fixed
description: sess41 ccloop: cache_coherency PASSES; 16-node posix blocker. FIXED AGI self-deadlock (E25DD67F). Remaining: INTERMITTENT 120s barrier dir-visibility…
metadata:
  type: project
---

# sess41 (ccloop run 14d31183) — 2026-06-12

## State shift
- **`cache_coherency` now PASSES** (4/4) on build `5D2D50C8` — the ~50-session blocker is resolved.
- Ship gate: **18 PASS, 1 FAIL**. Lone FAIL = **`posix_semantics_multi16`** (`elapsed>600s`), the 16-node `run_tests.sh --phase all` (single 12 + cluster 14 + stress 6). Single-node posix PASSES.

## FIX 1 (PROVEN, build `E25DD67F4CE7D18750E1A66`, KEEP) — AGI self-deadlock
- `test_concurrent_touch`@16 hung forever: test1 setup `mkdir` D-state (uninterruptible) on `xfs_buf_lock` for the **AGI buffer**; only ONE D-state thread = self-deadlock.
- Stack: `xfs_create → xfs_iunlink → xfs_iunlink_reload_next → xfs_irele → iput → xfs_inactive → xfs_ifree → xfs_difree → xfs_read_agi → xfs_buf_lock`. `xfs_iunlink` HOLDS the AGI; nested inactivation re-locks the same AGI buffer.
- Root: MXFS runs `xfs_inactive()` **synchronously** in `xfs_inode_mark_reclaimable` (xfs/xfs_icache.c ~2960) for multi-node (P25 recycle protection). Upstream queues inodegc (async) → no re-entrancy.
- FIX: gate sync-inactive on `current->journal_info == NULL` (XFS active-trans marker, xfs_trans.c:313). Nested-in-trans iput defers to async inodegc. Top-level unlink keeps sync. VERIFIED: no more wedge.

## REMAINING blocker — INTERMITTENT 120s barrier dir-visibility timeout (RULE 0)
- With deadlock gone, `posix(16)` still exceeds 600s. Cause: 3 tests (concurrent_touch, cross_visibility, dir_stress) intermittently hit a **120s barrier timeout** = ~459s overhead.
- **INTERMITTENT** (~50%): isolated `test_concurrent_touch`@16 fresh-mount measured 64s (no TO), 126s (TO), 140s, 172s (TO) across runs. So a load/timing race, NOT deterministic.
- **NOT burst-starvation**: in a 126s/TO run, ALL 16 nodes finished `touch_100_files` in <6.1s and logged timing → all 16 wrote their `ct_create_done` signal fast. Yet barrier saw 15/16 for 120s.
- **= reader-side dir-entry visibility gap**: one node's barrier-signal dirent (a create in shared `.mxfs_barriers/ct_create_done/`, likely shortform: 16 short names fit inline in dir inode) stays INVISIBLE to peers' cached view ~120s despite being on disk.
- Reader path: `xfs_readdir` for `XFS_DINODE_FMT_LOCAL` → `xfs_dir2_sf_getdents` reads in-core inline `dp->i_df.if_data` holding only IOLOCK_SHARED — NO inode DLM reacquire / FUA reload. Relies on async `EVICT-RING-DIRMOD` (sess80) push to invalidate; heartbeat-driven (2s), 28-deep ring, dedup 1-per-(ino,type) (dlm/disklock.c:984). At 16-node fan-out the evict intermittently doesn't deliver/converge → stale readdir for 120s.
- Standalone `tests/criteria/barrier_vis_repro.sh` (touch shared dir + poll, +burst, +concurrent-mkdir-barrier) ALWAYS converges 2-3s — does NOT reproduce. The real test's extra background traffic (hot `.mxfs_test/concurrent_touch` 1600-file dir BAST/drain/inactivation contending the same AG as the barrier dir) is the missing ingredient. NEXT: catch a TO run with present=[...] diag (added to tests/lib/cluster.sh barrier_wait) to confirm same-node-missing-for-all (pure visibility).

## This is the documented hard problem
- Same family as sess50 (CAW writer starvation barrier stall), sess79-92 (dir-block durable lost-update / reader staleness), sess131 (16-node same-dir storm 120s tail). Fix candidates: (a) reader pulls fresh dir-inode reload on shared-dir readdir (risk: per-readdir CAW poll regressed before — sess38/91 d_revalidate); (b) make EVICT-RING-DIRMOD reliable/synchronous at 16 nodes; (c) reduce cross-AG contention between barrier dir and hot data dir. NOT a quick fix.

## Infra notes
- Clean 16-node slate: `scripts/cluster_reset_n.sh 16` (power-cycle+prep, ~3.5min), then `tests/reset4.sh 16` (mkfs+mount). test1 can kernel-wedge (D-state) → needs virsh power-cycle not rmmod.
- Isolated single test: `MXFS_NODE_OFFSET=16 MXFS_TESTS_DIR=/src/mxfs/tests bash tests/run_tests.sh --nodes 16 --test test_concurrent_touch --pass-file /tmp/.mxfs_pass --device /dev/sda --mount-point /mnt/shared --no-color`. Results: `/home/steve/.mxfs/results/<ts>/test_*/node*.log` (CDT; +5h=UTC). Per-test `[Ns]` elapsed + 'timed out ... present=[...]' + `[TIMING] touch_100_files`.
- Orphaned run_tests.sh children survive a probe kill and keep ssh-retrying — pkill -9 -f run_tests.sh AND mxfs_test.sh AND the sshpass timing pattern.

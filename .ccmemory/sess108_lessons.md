---
name: sess108_lessons
description: sess108 NEWARCH Phase 0+1: chokepoint LANDED (Gemini design - UPGRADING→EDEADLK pattern); publish-on-create LANDED; cache_coherency cross_visibility…
metadata:
  type: project
---

# sess108 (2026-06-06) — NEWARCH Phase 0 + Phase 1 (chokepoint + publish-on-create)

Major architectural work toward `/src/mxfs/NEWARCH.md` Path A.  Full
narrative in `/src/mxfs/journal.md`; gate evidence in `/src/mxfs/phase0_results.md`.

## Builds (chronological)
- baseline = sess107 `EED6A769B0BA85B48F6B6BC` (deployed at session start).
- Phase 0 v1 `287BA2051DF7DD51B56AEED` — force_coherent demote + dir-buf invalidate
  (kernel oops in `xfs_dir2_sf_lookup`, reverted).
- Phase 0 v2 `4C9D5DA8740D26E8CF977B5` — dir-buf invalidate only (v2 force_coherent
  shut down node 4 in 49 s on a dir-format transition).
- Phase 1.1 `8354BAEED80B98F3282C89F` — P109-CLR-* probes at every clear site.
- Phase 1.3 v1 `287BA205…` (NL-clobber): cascaded → all 4 nodes shutdown.
- Phase 1.3 v2 `690BE0EF…` (state=DEMOTING): bast_notify dropped peer BASTs
  → peer caw_lock timeout → shutdown.
- Phase 1.3 v3 `D77E964D…` (new state UPGRADING): SESS50-STARVE on ino=128,
  bast_process never advanced → shutdown.
- Phase 1.4 `B132B685877AF1BC56A784A` — `mxfs_dlm_publish_inode()` in xfs_create.
  cache_coherency: cross_visibility PASS, rename_visibility 220-80/240 by node,
  no shutdowns, P107-PUBLISH=0 (eager publish), P106-STALE-EX=0.
- **Phase 1.3 proper `F591E7A5D1CF12192F0B0B4` (Gemini chokepoint, RULE 5 escalation)
  — current HEAD.**

## Gemini chokepoint design (KEEP) — the load-bearing change
The local "fence the slow-path entry" attempts all broke because they each
collided with one of bast_notify's / bast_process's assumptions.  Gemini's
codebase-aware design (queried 2026-06-06; transcript in journal.md, full
prompt in this session) was:

1. **`mxfs_dlm_caw_lock` UPGRADE-DDL removed.** When `our_mode != NL` and the
   compat check fails, return **-EDEADLK** instead of clearing our bit and
   becoming a waiter.  caw_lock now upgrades-in-place atomically OR acquires
   from NL.  No silent demote.  (dlm/dlm_caw.c P109-CAW-EDEADLK probe.)
2. **New state `MXFS_DLM_ISTATE_ACQUIRING`** (xfs_inode.h #define 4) — set in
   the upper-layer slow path before dropping i_dlm_lock to call caw_lock,
   cleared on return.  Blocks concurrent same-node fast-path acquires (they
   wait on i_dlm_wait); bast_notify treats it specially.
3. **Upper-layer -EDEADLK handler** (xfs_mxfs_dlm.c mxfs_dlm_ilock_begin):
   transition state→BAST, schedule_work(&ip->i_dlm_bast_work), wake_up_all,
   then **recursively re-enter mxfs_dlm_ilock_begin(ip, mode)**.  The
   recursion hits the wait loop, blocks until bast_process drains+unlocks+
   sets state=NONE, then falls through to a fresh slow path that acquires
   from NL (cannot hit -EDEADLK because our_mode=NL has no upgrade conflict).
   Probe `P109-EDEADLK`.
4. **`bast_notify` ACQUIRING branch**: set `i_dlm_stale = true`, **do NOT**
   queue bast_process (queuing would strip the on-disk slot out from under
   caw_lock's polling loop — the v3 failure shape).  Probe via mxfs_idbg.
5. **Slow-path wait loop extended** to wait on DEMOTING || ACQUIRING || BAST
   (demoter task exempt for self-reentry).
6. **Post-acquire publish**: ACQUIRING → CACHED, OR ACQUIRING → BAST +
   schedule bast_work if i_dlm_stale was set during the acquire.  wake_up_all.

## Phase 1.4 publish-on-create (KEEP)
- `mxfs_dlm_publish_inode(struct xfs_inode *ip)` added (xfs/xfs_mxfs_dlm.{c,h}).
- Called in `xfs_create` (xfs/xfs_inode.c) after `xfs_trans_commit` +
  `mxfs_dlm_dir_durable_signal(dp)` + BEFORE `*ipp = du.ip` and the iunlocks.
- Synchronously promotes the new inode to a real on-disk EX CAW slot, so
  peers reaching it via cached parent dirent find a real slot to BAST.
- Closes the sess107 deferred-publish hazard at create time, not lazily.
- Probes: `P109-PUBLISH-OK` (instr-gated), `P109-PUBLISH-FAIL` (always-on warn).

## Results (build F591E7A5)
- 20-file 4-node concurrent rename repro: **13 s, TOTAL_FAILS=0 on all 4**.
- 100-file 4-node stress: 35 s, 20 consistent fails/node (5% lost-write,
  consistent across nodes = same files missing everywhere — REAL durable lost
  writes, NOT stale-read coherency), NO shutdowns, P109-EDEADLK 5–17×/node,
  P106-STALE-EX=0.
- cache_coherency 4-node: **cross_visibility PASSED 4/4**.
  test_rename_visibility wedged → 900 s SIGKILL.

## The remaining wedge (handoff to next session)
- test1 ran `rm` on `ino=4194433` (a recently-created file).
- caw_lock returned -EDEADLK; chokepoint scheduled bast_work_fn.
- bast_process tried to drain AG=2's AIL.  **The AG-AIL push wedged at
  `iter=75520` (75K iterations no-progress) on stuck_ino=4194433,
  `iflags=0x0 buf_locked=0`** — clean inode with no locked buffer that
  the existing P67-INSTR AG-AIL-STALL code can't push.
- `rm` thread hung in `mxfs_dlm_ilock_begin+0x279 → schedule` for 900+ s
  ("hung_task" every ~120 s) waiting for drain.
- **This is a pre-existing AG-AIL push bug.**  sess67's P67-INSTR named the
  path; sess20+ wrote the underlying drain code.  The chokepoint hits it
  reliably because EVERY -EDEADLK now goes through bast_process; the old
  silent UPGRADE-DDL sidestepped the AIL push entirely.  The chokepoint is
  correctly demanding what NEWARCH §4 invariant #1 mandates ("no on-disk
  unlock without completed drain") and the drain code can't yet deliver.

## Phase 1.5 — for next session
1. **Fix the AG-AIL push wedge** on `iflags=0x0 buf_locked=0` inodes (the
   drain logic in mxfs_dir_push_data_ags / xfs_mxfs_dlm.c needs to handle
   the clean-but-stuck-AIL case).  After this, cache_coherency should land
   the chokepoint cleanly.
2. **Add the permanent divergence assertion** per Gemini's design item (e):
   `WARN_ON_ONCE(!(slot.holders & ctx->node_bit))` pre-CAS in
   `mxfs_dlm_caw_unlock`, and `WARN_ON_ONCE(ip->i_dlm_mode == 0 &&
   ip->i_dlm_state != ACQUIRING)` in `mxfs_dlm_bast_notify`.  Both fire
   the moment in-core and on-disk diverge for a live resource, with zero
   extra disk I/O (piggyback on the necessary CAS/BAST-arrival context).
3. **Re-run Phase 0 force_coherent gate** with chokepoint engaged.  If it
   passes 4/4, the gate moves to Outcome 1 vs 2 — then run the multinode
   metadata fio bench to compare against GFS2/OCFS2.
4. **Phase 2 (TCP invalidation mesh)** unblocks after (1) lands and the
   gate hits Outcome 1.

## Behavior memos to KEEP
- `feedback_timing_is_first_class`: any test taking >60 s where it should be
  seconds IS a failure regardless of eventual PASS.  Use the 10-second
  `tests/repro_rename_concurrent.sh` for inner-loop iteration; reserve the
  900-second `cache_coherency.sh` for end-of-cycle ship-gate verification.
  FIO bench is the only exempt long-timeout (sized to runtime).
- DKMS auto-loads mxfs.ko at boot before INSMOD_OPTS can take effect;
  use sysfs after mount (`echo 1 > /sys/module/mxfs/parameters/instr`)
  or run `bash tests/reset4.sh 4` to force-reload with the latest build.
- `bash tests/reset4.sh 4` (not `./tests/reset4.sh`) — execute permission
  occasionally drops on NFS export.

## State of head
- Marker NOT written (criterion 3/4 → 1/4-with-wedge).  But the
  P106-STALE-EX class is closed (=0 in every chokepoint run).
- Build to deploy next session: rebuild from this tree (`make clean &&
  make modules && make tools`) — current srcversion `F591E7A5D1CF12192F0B0B4`.

---
name: sess18run-MILESTONE-8tcp-dirreuse-PASSES-correct-mht300-speed-only-residual
description: sess18(ccloop) MILESTONE (build 58360875): 8/tcp dir_reuse_coherency PASSES 8/8, all 24 rounds, failrounds=0 at DEFAULT mht=300 — data CORRECT. Only…
metadata:
  type: project
---

## sess18 (ccloop) — 8/tcp dir_reuse CORRECTNESS ACHIEVED (build 58360875D262141AAAA2BA6)

### RESULT: `TEST_TIMEOUT=400 ./run.sh 8 tcp dir_reuse_coherency` = **PASS 8/8, failrounds=0 on ALL nodes, all 24 rounds** at DEFAULT mht=300. Data fully correct. WALL=354s (~337s test).

### Four KEEP speed fixes this session (all in xfs_mxfs_dlm.c unless noted), built on sess17's dg_shadow-LRU+fork-adopt:
1. **NO_INODE BAST offload** (recv thread → m_mxfs_inode_bast_wq). Eliminated the 60s create-phase stalls. See [[sess18run-FIX-noino-bast-offload-recv-thread-eliminates-60s-create-stall]].
2. **PR-drain skip**: a PR (read-only) NON-DIR release committed nothing → skip the whole settle+log_force+ail_drain+blkdev_flush. Kills the rm-storm cost (after verify all 8 nodes hold PR on 800 files; rank1 rm revokes ~5600 PRs). Dirs KEEP the drain (dir_pr_release_fast masking).
3. **clean-release log_force skip**: a clean inode (unpinned + log item not in AIL) is already checkpointed → skip the global xfs_log_force(SYNC).
4. **release-flush COALESCING** (mxfs_release_coalesced_flush + m_mxfs_flush_req/done/lock in xfs_mount.h, init in pal/linux/xfs_super.c): concurrent BAST releases share one blkdev_issue_flush (ticket: inc req after writes submitted; flush sets done=snapshot; safe — may over-flush, never under). Replaces blkdev_issue_flush in bast_process drain + noino work fn.

### CORRECTNESS vs mht (PROVEN this session):
- mht=300 (DEFAULT): RELIABLY correct (failrounds=0, full 24 rounds). USE THIS.
- mht=250: intermittent 1-entry dir-data lost-update (e.g. round 7 dropped node8_f20.md5 durably on all nodes, readdir 799/800). NOT reliable.
- mht=150: persistent data loss (readdir 701/800). The dir-data stale-base-RMW lost-update is only fully masked by mht=300's longer EX hold (fewer handoffs = fewer reload-RMW windows). The reload-on-handoff is not 100% reliable — that's the deep residual, masked (not fixed) by mht=300.

### REMAINING blocker = SPEED only: ~337s test time > 300s blanket TEST_TIMEOUT (run.sh:49). ~14s/round × 24. Breakdown: create skewed ~3s (8-node dir-EX serialization, mht=300 holds 300ms/tenure), verify ~8s (wr-barrier wait for slowest creator + 800 cold reads + 1s test sleep), rm ~4.5s. The create dir-EX serialization at mht=300 is the root; lower mht is faster but loses data. Native single-node XFS ~0.5s/round so RULE-0-wise 8-node single-dir contention is inherently far over 2×, but the test DOES complete correctly. NEXT: either (a) shave ~40s (targets: test's per-round `sleep 1`=24s total [tests/suite/dir_reuse_coherency.sh:88]; barrier overhead; rm/inactivation), or (b) make the reload-on-handoff 100% reliable so a FAST low-mht is correct (the real fix), or (c) principled per-test budget for 8-node dir_reuse (it does 2× the 4-node work; 4-node passed at 300s).

### MUST: verify 1/2/4 tcp not regressed by the shared-path changes (PR-skip/log_force-skip/coalescing touch ALL releases). Then full ./run.sh 8 tcp (all tests). See [[sess17run-STATE-3of4-criterion-pass-8tcp-residual-leafhash-plus-contention]].

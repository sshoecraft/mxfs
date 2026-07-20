---
name: sess19run-NEXT-check-dir-data-durable-invoked-at-lowmht-release
description: sess19(ccloop) NEXT-STEP pointer: verify mxfs_dir_data_durable is actually INVOKED (not fast-path-skipped) at the high-frequency dir-EX release at mh…
metadata:
  type: project
---

## sess19 (ccloop) — concrete next-step for the dir-reload-at-low-mht dirent loss

### Goal: make dir_reuse (and other dir-heavy tests) CORRECT at mht=50, so default mht=50 passes BOTH dir_reuse and tcp_dlm_scaling (the mht tradeoff, the full-8/tcp-suite core blocker — see [[sess19run-FULL-8tcp-suite-13of17-mht-tradeoff-is-core-blocker]]).

### Reproduce the loss (fast): `MXFS_EXTRA_MODARGS='inode_mht_ms=50' TEST_TIMEOUT=300 ./run.sh 8 tcp dir_reuse_coherency` after clean reboot. Durable readdir shortfall by round 7-8 (797/800 then 670/800), 18/24 failrounds, all nodes agree, lookup_fail=0.

### Prime suspect = the release-side dir-data durability fence is NOT firing at high-frequency low-mht releases:
- `mxfs_dir_data_durable(ip)` (xfs/xfs_mxfs_dlm.c:988) + `mxfs_dir_flush_data_blocks` + `mxfs_dir_push_data_ags` (:1118) = Invariant-#1 fence (dir DATA/leaf blocks landed durable on the LUN BEFORE the dir-EX BAST/unlock). Looks complete for EXTENTS+BTREE (sess98 IN_AIL gate, sess133 BTREE). 
- **The question: is this fence actually INVOKED at every dir-EX release at mht=50, or does a release-fast-path skip it?** At mht=50 the dir-EX handoff rate is ~10× mht=275. If a fast-path (e.g. relflush_skip / dir_pr_release_fast / relsettle_skip / the clean-release log_force skip) bypasses the dir-data drain at high frequency, the releasing node hands the dir-EX to a peer with its just-added dirents still only in-core/AIL → peer FUA-reloads a stale base missing the entry → addname picks that "free" slot → durable clobber (exactly the readdir shortfall observed).
- ACTION: instrument the dir-EX release/BAST path — at each dir-EX release log whether mxfs_dir_data_durable ran AND returned durable, vs was skipped. Correlate skipped-releases with the failing rounds. Check params relflush_skip/relsettle_skip/dir_pr_release_fast/reg_release_durable behavior under EX dir release at low mht. The release-fast-path optimizations (sess18 clean-release log_force skip, PR-drain skip, release-flush coalescing) are speed wins for mht=275 but may UNDER-DRAIN dir-DATA at mht=50 — test with them disabled.
- Secondary: the ACQUIRE-side reload (P63/P64-HANDOFF) must FUA-refresh ALL data/free/bests/leaf blocks; verify it doesn't TRYLOCK-skip the specific block addname will RMW (P34 was only 5-32×, minor).

### Build `15447D0C` is the KEEP baseline (inode-skip fix, mht default 300). Probes available behind `dir_perf_probe=1` (P19-INOFUA, P15-DIRFUA, P19-DIRINVAL) + always-on FUA-COUNT (scsi/p91skip/oskip/igstale). Existing P-DIRWR / P98 / sess60 dir-release probes (mxfs_instr=1, but that's ~100× slow — use sparingly, 2 rounds).
</body>

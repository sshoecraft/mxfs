---
name: ccloop-c7ee71c6-sess387-cascade-fixed-pace-now-blocks
description: sess387: #361/AGI cascade ELIMINATED across 3 builds (0 shutdowns at lap2, first ever); obligations+target-flush+convert-before-adopt landed; lap-2 r…
metadata:
  type: project
tags: [sess387, agi-unlinked, 361, obligations, pace, closure]
---

## sess387 fix set (0.19.25 → 0.19.33, all verified at 32/caw TREATMENT laps)

1. **0.19.25**: named every silent -117 exit (P82-ADD-FAIL stage=, P-IUNL-INSFAIL/
   LOGSAME/BUCKETSAME). Root confirm: acquirer's xfs_iunlink_reload_next reads a
   split member, cached=0, home nlink=1.
2. **0.19.26**: `mxfs_iflush_agino_target` (xfs_inode.c, exported via
   xfs_mxfs_dlm.h) — mandatory deadline-aware single-inode flush (ILOCK→buffer
   order, trylock+backoff loops, IFLUSHING interlock, li_buf buffer,
   merge_dirs before bwrite, raw ILOCK un-take per sess16). P87 repair rewritten
   on it; `publish_repair_budget_ms` (3000) aggregate per release.
3. **0.19.27**: publication-obligation store `mxfs_pubob_*` (near iunl store in
   xfs_mxfs_dlm.c), flags MXFS_IF_PUBOB(1<<30)/_FLUSHED(1<<31): armed at
   xfs_iunlink, FLUSHED at iflush copy-in (nlink==0), discharged at
   iflush_finish/list-removal; enforced at AG release incl. mid-chain members.
4. **0.19.28**: audit verify reads ACQUIRER semantics — plain read under
   fua_disable=1 (FUA platter read manufactured false splits + burned budget).
   P87-TARGET-TIMEOUT stage attribution (ilock/pin/buflock/iflushing).
5. **0.19.29**: P88-PUBOB-RECLAIM tripwire → caught shells dying 720ms after
   P82-ADD with flushed=0.
6. **0.19.30**: reclaim REFUSES live-obligation shells (unless unmounting);
   P88-PUBOB-FIELDSCLEAR probes at mark_stale/abort_clean. **FIRST EVER 0-shutdown
   lap 2.**
7. **0.19.31/.32**: the corpse ROOT chain named by probes: P15-REL-ABORT
   re-acquire window → P119 fence (mode=3 while disk EX ours) → **sess382
   reldefer reload ADOPTS platter over unlanded conversion (P177)**. Fix =
   sanctioned convert-before-adopt (P245-REL-OBLIGATION-CONVERT, RELFLUSH set
   around mxfs_iflush_agino_target inside the deferred-release worker; measured
   rc=0). Also added at the P236 obligation_only defer (fires rarely; P244/
   reldefer is the hot path).
8. **0.19.33**: bounded in-place deferral at AG release (2×2s+re-audit) before
   publishing/refusing an unrepaired split (P87-PUBLISH-DEFER-EXHAUSTED).

### Measured outcomes (laps 2, historically 1-3 node deaths + cascade)
0.19.30: 0 shutdowns, 32/32 mounts OK. 0.19.31: 1 shutdown (separate noino
relfence #474 site). 0.19.32: 0 shutdowns; P245 rc=0 conversions; P177 drops only
from ACCESS-path reloads (no exclusion → can't convert there; release enforcement
covers them via surviving store entries).

### Closure blockers for D-AGI-.../-361 (per d385 bar)
- (a) residual ILOCK-across-CAW-poll splits → 0.19.33 deferral, measure.
- (b) **LAP-2 PACE**: rsync stragglers 47-54s vs 16s median (rename-over-existing
  delta lap), budget exhaustion + done-barrier fail on all 32. THE closure
  blocker. Stragglers ≠ refusal-heavy nodes (checked). Lap 1 flat 16-19s across
  ALL builds → no build-to-build regression from the fix set.
- (c) then the formal d385 CONTROL+TREATMENT 3-lap protocol.

### Traps
- The d385 arm_collect harvest MISSES probe lines (grep live dmesg instead).
- P82-ADD/P140 caps are module-global (prep does NOT reload module unless build
  changes; counters persist across laps).
- run.sh copies FAIL logs to /tmp/run_<test>_<RUNID> before deleting tmpd.

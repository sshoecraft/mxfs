---
name: AAA-ccloopa864-sess2-ROOT-orphan-EX-bit-stale-DEMOTING
description: sess2 ROOT FOUND: dir_reuse@32 wedge = ORPHANED on-disk EX holder bit at reuse boundary. Holder stuck in stale DEMOTING (P72-SWALLOW ×41) + inode_hel…
metadata:
  type: project
---

# dir_reuse@32 ROOT — orphaned on-disk EX holder bit + stale DEMOTING

## THE ROOT (instrumented, B6 v0.10.43 P-ACQ-STUCK probe)
The wedge is NOT fairness (B2-B5 fairness work was the wrong tree). It's a **phantom/orphaned on-disk EX holder bit** at the dir-reuse boundary.

### Direct evidence
P-ACQ-STUCK (new probe, dlm_caw.c caw_wait_for_grant loop, dumps full on-disk slot when acquire >15s) on test5, want=5(EX), stable across ALL dumps (gen FROZEN):
```
gen=2417(frozen) gm=5 hex=80000000 hpw=0 hpr=0 w=3950e49a wex=3940e49a yt=0 streak=1
```
hex=0x80000000 = bit31 = **test32 holds dir EX on disk, gen frozen (no release CAS ever happens)**. All 31 peers wait → 360s → rc=-110 shutdown.

But test32's INCORE view (P7B-BASTNOTIFY flood at 339s): `state=0(NONE) mode=0(NL) ex=0 pr=0`. So test32 thinks it holds NOTHING while the disk slot says it holds EX = ORPHANED BIT.

### Why the orphan never clears (TWO compounding bugs, both in xfs_mxfs_dlm.c bast_notify)
1. **Stale DEMOTING**: test32 fires **P72-SWALLOW-DEAD ×41** — bast_notify line ~14189 `if (state==DEMOTING)` swallows the BAST (work_busy=0 = no live demote instance). This is the sess4 lost-BAST wedge the code DETECTS (P72 probe) but does NOT RECOVER from — it just `xfs_irele; return`. So every peer BAST is swallowed, orphan never released.
2. **inode_held returns 0**: test32 NEVER fires P135-ORPHAN-RELEASE (0×) or P135-GRANTWIN-PARK (0×). The orphan-release path (line ~14378, `p135_held==1 && grant_gen==0` for CAW) requires `mxfs_v5_dlm_inode_held(ino)==1`. It returns 0 despite the disk bit being set → the NONE/NL branch also fails to clear. (Need to confirm: does inode_held read the live disk slot or a stale incore mirror for CAW?)

### test32 release timeline
r2 create-done 261.7s. At 261.9: P106-EXREL rel_gen=7317, P70-BP EXIT=full ex=0 pr=0 (a CLEAN release). P60-RELAUDIT flagged "INCONSISTENT-AT-RELEASE" (di_nextents=27 leafsum=63 nleaves=2). Then test32 re-acquired (slot gen climbs to 2417) and THAT tenure orphaned — incore state reset (reuse frees ino131 → fresh inode NONE/NL) while disk EX bit persists (resource_id has no inode-gen, so reused ino131 = same CAW slot; see AAB-dlm_scaling32 memory).

## FIX DIRECTION (candidates, not yet impl)
- **Stale-DEMOTING recovery**: when BAST arrives, state==DEMOTING, work_busy==0 (P72 condition) → RE-QUEUE bast_work (or reset to allow re-process) instead of swallow. Recovers the stuck release.
- **inode_held/orphan**: make the CAW BAST path read the LIVE disk slot; if OUR bit is set but incore is NONE/NL, force the serialized orphan-release regardless of the (stale) mirror.
- **Prevent orphan at source**: when ino is FREED/reused (rm-rf recreate), if THIS node holds the on-disk EX bit, clear it as part of the free (relates to AAB-dlm_scaling32 caw_epoch_free_reset, but for the HOLDER bit not just epoch).

## Build state
v0.10.43 srcver B0F87A63 = B6, has P-ACQ-STUCK probe + carries B2-B5 fairness changes (yield_set_ms don't-re-arm; no streak-reset; upgrader-defer INERT). The fairness changes are orthogonal to this root — keep or revert later. dir_reuse coord: rank1(test1) rm-rf+recreates dir ino131 each round; NFILES=50; per-test budget 140*32=4480s.

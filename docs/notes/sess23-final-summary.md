# Sess23 Final Summary

## Where we ended up
- **v0.3.83 in tree**, deployed to .186 + .182 (srcversion CC0894082993D2BF7944099)
- **Source clean**: no leftover diagnostic, no aborted experimental fixes
- **CLAUDE.md hardened** to make Rule 2 (don't stop without ccusage>90% or user request) unambiguous
- **Test infrastructure rebuilt**: stress script checks dd/rm exit, uses UTC, doesn't clear dmesg

## Headline finding
**Sess22's "3 PASS runs" were FALSE POSITIVES.**  The previous stress
script only inspected dmesg for corruption markers, didn't check that
dd actually succeeded.  Re-analysis of sess22 logs:

| Sess22 log | T1_DD_OK | T2_DD_OK | T2 errors | Reported |
|---|---|---|---|---|
| v382_clean1 | 15 | **0** | 30 | "PASS" *(false)* |
| v378_run3 | 15 | **0** | 15 | "PASS" *(false)* |
| v380_run4 | 15 | **0** | 15 | "PASS" *(false)* |

T2's mount was already shutdown from prior wedge; every T2 dd hit EIO,
but dmesg-cleared check missed it.  T1 alone iterated cleanly because
no peer was actively coordinating.

## Real fix made
**v0.3.83**: `dlm/dlm_caw.c::slot_appears_corrupt` and `caw_repair_slot`
now detect garbage holder bitmaps via popcount.  Specifically:
- `popcount(holders_ex) > 1` → corrupt (EX is exclusive)
- `popcount(holders_pw) > 1` → corrupt (PW is single-writer)
- `granted_mode != recompute_granted_mode(slot)` → corrupt
- Repair zeros invalid h_ex/h_pw instead of preserving them

ROOT CAUSE: P13-INSTR captured ino=128 slot=51123 with
`hex=e0041d00e1000413` — popcount=16 in EX bitmap.  Stale-disk garbage
from prior FS that mkfs's pwrite-O_SYNC didn't durably overwrite on the
LIO target.  Existing repair (v0.3.30) only checked granted_mode/
waiter_mode; garbage in holders bitmaps slipped past, blocking peer
acquires for 120s until DLM timeout.

## Validation results

| Stress mode | Cycles | PASS rate |
|---|---|---|
| no-drop_caches | 4/4 confirmed | **100%** |
| with-drop_caches | ~3/8 across the session | ~40-60% |

**v0.3.83 status:**
- Real production-style workload (no drop_caches): release-quality.
- Aggressive drop_caches stress: intermittent, ~50% PASS, with bnobt
  LEFT/RIGHT-FAIL or "Free inode N has blocks allocated" failures.

## Failed fix attempts (all reverted)

| Attempt | Result |
|---|---|
| Skip reclaim from drop_caches in xfs_fs_free_cached_objects | dd hang from infinite FUA reads |
| log_force + ail_push_all_sync barrier in shrinker | dd hang (ail_push too expensive on 1863-AG fs) |
| Return 0 from xfs_fs_nr_cached_objects | broke memory-pressure reclaim |
| REQ_FUA on AG-meta WRITES | no improvement, possibly worse (matches v0.3.74 reversion) |
| LRU ref bump 2→256 for AG-meta | similar variance to baseline (1, 15, 7 iters / 3 runs) |
| skip-FUA-on-BLI in xfs_buf_submit | both bio + FUA paths overwrite, doesn't help |

## Unfixed: Bnobt LEFT/RIGHT-FAIL family

P28 captures: `leaf_buf daddr=0x8 flags=0x30 b_log_item=NON-NULL hold=N`
at corruption time.  The bnobt root buf has BLI attached (we modified)
but content shows pre-modification state — meaning a re-read fired on
the buf with un-flushed BLI, overwriting in-memory mods.

P32-INSTR captured stale events at corruption time:
- `xfs_buf_ioend_fail` (failed-write completion)
- `__xfs_buf_ioend` (normal completion + out_stale path)

These are EFFECTS of the corruption's xfs_force_shutdown causing
pending I/Os to fail.  NOT the cause — the bnobt corruption fires BEFORE
the stales (xfs_alloc.c:2106 LEFT-FAIL or :2162 RIGHT-FAIL).

The actual cause of bnobt content getting wrong remains unidentified.
Drop_caches is the trigger but the mechanism isn't visible from current
diagnostics.

## NEXT SESSION PRIORITY

1. **Bnobt LEFT/RIGHT-FAIL fix** (sess22's true priority-1).  Approach:
   diagnostic that fires AT EVERY bnobt root buf modification, comparing
   in-memory content vs disk content.  When they diverge during T2's
   exclusive hold, that's the moment.
2. Strip P14/P15/P22/P23/P25/P28/P29/P30/MX-INSTR diagnostic prints
   (timing-perturbation risk; some may have caused intermittent failures
   in earlier sessions — see don't-repeat list).
3. xfs_extent_busy cross-node audit (sess21 strategy #1, still open).

## Don't repeat (sess23 additions)

- Returning 0 from xfs_fs_free_cached_objects in multi-node mode.
- Returning 0 from xfs_fs_nr_cached_objects.
- log_force + ail_push barrier in xfs_fs_free_cached_objects.
- REQ_FUA on AG-meta writes (already in sess14-22 list as v0.3.74).
- LRU ref bump for AG-meta to high values.
- skip-FUA-on-BLI in xfs_buf_submit hook.

Plus all sess14-sess22 don't-repeat list entries.

## Files in sess23

- Source: `/src/mxfs/{dlm/dlm_caw.c, mxfs.ko}` — v0.3.83 popcount fix.
- Stress: `/tmp/mxfs_stress_v033.sh` — fixed (UTC, dd/rm exit checks).
- Stress no-drop: `/tmp/mxfs_stress_no_drop.sh` — variant without drop_caches.
- Reset: `/tmp/mxfs_cluster_reset.sh` — handles transient rmmod-busy.
- Logs: `/tmp/v38*_*.log` — comprehensive sess23 stress data.
- State: `/src/mxfs/state.md` — sess23 handoff at top.
- Memory: `~/.claude/projects/-src-mxfs/memory/sess23_lessons.md`.
- This summary: `/src/mxfs/sess23-final-summary.md`.

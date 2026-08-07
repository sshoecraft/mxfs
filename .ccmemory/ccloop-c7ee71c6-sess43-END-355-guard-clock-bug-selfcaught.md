---
name: ccloop-c7ee71c6-sess43-END-355-guard-clock-bug-selfcaught
description: sess43 END: 0.11.355 BUILT (guard clock bug self-caught, not deployed); 354 board green + PR-flush defect CLOSED; 11 OPEN
metadata:
  type: project
---

# sess43 END — state for the next session

## BUILT BUT NOT DEPLOYED: 0.11.355 (srcversion 5B137EF3EB7AD51B726EBD1)
**Fixes a real bug I introduced in 353/354 and caught by self-audit before
claiming any closure.** The recovery GUARD's staleness test compared
`mxfs_pal_time_ms()` (= `ktime_get_boottime_ns()/1e6`, each node's own UPTIME)
against the record's timestamp. Across nodes with different uptimes — the
normal case — a FRESH guard computes a delta of hours and reads as stale, so
peers would claim a guarded slot mid-sweep: **the cluster-visible exclusion GPT
ruled mandatory was not actually in force on 353/354.** Exactly the trap
tests/hb_live_count.sh documents (HB timestamps are comparable only to
themselves), which I had written hours earlier and failed to apply to my own
kernel code.

Fix shape (dlm/disklock.{c,h}, xfs/xfs_mxfs_dlm.c):
- `hb_guard_stale()` → **`hb_guard_abandoned(ctx, slot, first)`**: re-read the
  record after ~3 × `MXFS_DISKLOCK_GUARD_REFRESH_MS` (1000ms) and treat NO
  MOVEMENT as a dead holder. Change-detection only — no cross-node clock math.
  `MXFS_DISKLOCK_GUARD_STALE_MS` removed.
- Both `claim_slot` variants now **skip GUARD records unconditionally** (never
  steal, never judge — the claim path is latency-critical at mount). Safe:
  64 slots, and an abandoned guard is reclaimed by the next live sweeper's
  `guard_slot`, so a dead holder cannot strand a slot permanently.
- `mxfs_unclaimed_bucket_scan` refreshes the guard **per AG**, which is what
  makes the timestamp visibly move while the sweeper is alive.

**NEXT SESSION STEP 1: deploy 355, re-verify** — torn-shape unlinker_death
iterations, the cold-side unclaimed-bucket path (P99-GUARD → P97 → P89), and a
board chunk. Then build the joiner-vs-guard race arm (now easy: hold a guard,
join a node, assert it claims a DIFFERENT slot).

## SHIPPED + VERIFIED EARLIER THIS SESSION
- **0.11.354: D-UNMOUNT-RELEASE-FLUSH-AFTER-PR-UNREGISTER → FIXED AND
  VERIFIED.** `xfs_shutdown_devices()`'s unconditional `blkdev_issue_flush()`
  ran after the deferred PR unregister, so every clean unmount of a PR LUN
  ended in a rejected Synchronize Cache. Unregister moved after it (that
  function only flushes/invalidates; bt_bdev still valid). Verified: 24 clean
  unmounts, ZERO failed I/O (tests/unmount_flush_clean.sh).
- **Board green on 354 at 32/caw AND 8/caw**: 22 PASS, 5 FLAKY(current-PASS),
  0 FAIL, 1 POLICY.
- **Torn-shape tally for D-DESTAGE-TEAR**: 354 @32 nodes — 4 iterations, 3 TORN
  and all 3 adopt→P89 free (chain confirmed on ino=537709), 1 bucketed; plus
  4/4 on 352. Zero leaks. Closure still blocked on 355 verification + the race
  arm (recorded in the ledger's status_note_sess43).

## LEDGER: 32 entries, 11 OPEN (gate now counts correctly)
`open_defects.sh` had counted `status != "RESOLVED"` as open, reporting
**26 of 31** when 11 were OPEN. Fixed in both the python and grep-fallback
branches against {RESOLVED, FIXEDANDVERIFIED, FIXEDVERIFIED, DISPROVED}; any
UNRECOGNISED status still counts OPEN so nothing closes by typo.
New this session: D-CACHE-COHERENCY-UV-COUNT-MISS-2332 (critical, arithmetic
root: rank1's unique `uv all files present pre-delete` assert),
D-CRASH-CONSISTENCY-32-NOTERMINAL-354 (major, unreproduced in 3 re-runs at
double the load; P15 storm excluded by measurement).

## RIG STATE
32/caw prepped on **0.11.354** (2DDE66BFEB1DC5B3D3B6042), all 32 mounted,
`dir_ex_batch_grace_ms` restored to 10. Tree VERSION=0.11.355, mxfs.ko is the
355 build — **deploy before running anything and the marker will mismatch**.
Host load swings 12→44 during a session; every result now carries `hostload=`.

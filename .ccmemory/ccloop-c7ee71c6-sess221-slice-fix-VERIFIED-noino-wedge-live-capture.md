---
name: ccloop-c7ee71c6-sess221-slice-fix-VERIFIED-noino-wedge-live-capture
description: sess221: log-slice fix VERIFIED (load-kill slot30, slice 30/32, 0 NOSLICE fleet-wide); #18 noino-wedge captured LIVE (ILOCK-over-CAW-poll proven, sta…
metadata:
  type: project
---

# sess221 — slice-fix load-kill verification + two major captures

## D-LOG-SLICE-SHARED-MULTIWRITER (#20) verification PASSED
`tests/incident474_load_kill.sh 32 test28 180` on 0.11.479 (sv 977E252C3ABEF4192431F53), kill 2026-08-10T20:51:15Z:
- test1 (recovery owner): `foreign replay of dead slot 30 (slice 30/32)` — identity mapping (not modulo) live; replay clean through P163-RECOVERY-COMPLETE, tokens evaluated (P227-TOKENSUM 6/6, ATOMIC-SKIP correct).
- Fleet sweep, all 31 survivors: P238-FENCE-NOSLICE fired 0 times; foreign-replay errors 0; all mounted.
- Remaining for closure: full board (`./run.sh 32 caw`) + ledger fold-in of GPT-ruling extras (mixed-version gate, slot-reuse race, no-stale-clear-after-find_tail-fail; kernel geometry validation DONE sess220).
- Trap: rc=-5 lines AFTER a node's own fence are SCSI reservation conflicts (post-preempt) — not replay failures.

## #18 D-NOINO-RELFENCE-AIL-FREEZE-474 — first fully-instrumented live occurrence
On test1 (recovery owner), same run:
1. rm (load loop) in xfs_inactive_truncate holds ILOCK(2931), blocked in caw_wait_for_grant on AG0 (victim-held grant frozen until replay+purge). **P-AILMIN @277s dumped the rm stack — the OPEN "ILOCK held across CAW poll" (a2) hypothesis is now PROVEN live.** P137-INACT-TIME total 93.5s.
2. AIL min = INODE lsn 0x100002da7; its flush needs that ILOCK → P129-CLSKIP ILOCK_NOWAIT_FAIL → AIL frozen.
3. @287.13s P-NOINO-DRAIN-STUCK try=8 → P-NOINO-RELFENCE-WEDGE → forced shutdown (xfs_mxfs_dlm.c:19526) — **17s before purge completion (303.7s) would have freed AG0**. The wedge detector escalated during a legitimately bounded recovery wait; needs to be recovery-aware (or a2 removes the blocking wait).
4. Cascade CONTAINED: only test1 died; peers replayed slot 0 cleanly.

## NEW unledgered defect — recovery path holds disklock ctx->lock ~35s
`P-HB-SLOW slot=0 write_ms=0 lockwait_ms=34978 rc=0` at 303.732s — hb thread waited on ctx->lock for the whole recovery stage 3→5 window (267.9→303.7s), unblocked the same millisecond P163-RECOVERY-COMPLETE printed. >half the 62s lease; also delayed the withdraw stamp 16s. If purge ever exceeds the lease, the recovery owner self-fences → cascade. Precedent: disklock.c:2332 (sess38 fixed identical pattern in read_all with per-slot lock/unlock). Suspect sites: mxfs_disklock_purge_node (disklock.c:2029, 65536-slot FUA scan) / recovery_complete path (v5_mount.c ~3449). Ledger as new high defect or fold into #19.

## Rig state at handoff
test28 destroyed, test1 shutdown+withdrawn (VM up); 30 nodes healthy on 0.11.479. Board run will re-prep (prep_fs.sh mkfs -n ${MXFS_LOG_SLICES:-32}).

---
name: ccloop-c7ee71c6-sess9-B-D2-withdraw-replay-barrier-VERIFIED
description: sess9-B: D2 landed+VERIFIED v0.11.103 — withdraw=death stamp, purge deferred behind elected slice replay; withdraw_recovery_test PASS (detect 1.5s, r…
metadata:
  type: project
tags: [withdraw, foreign-replay, D2, verified, sess9, P163]
---

# sess9-B — D2 (withdraw/recovery ordering) LANDED + VERIFIED at v0.11.103 (2A3955E92692849839D139C)

## What landed (v0.11.102→103)
- **D1b** (pal/linux/xfs_buf.c P110 undest branch): set `b_mxfs_inplace_read = true` before
  xfs_buf_ioend — in-place read completion no longer runs verify_read on dirty in-core content
  (the manufactured EFSBADCRC → t1 shutdown trigger of drc r13). Mirrors the P91 path's v0.10.32 flag.
  P126 left UNCHANGED (with the CRC trip gone its stale+serve is benign; no proven harm remains).
- **D2** across dlm/disklock.{h,c}, dlm/v5_mount.{h,c}, xfs/xfs_mxfs_dlm.c:
  - MXFS_DISKLOCK_FLAG_WITHDRAWN=2; mxfs_disklock_withdraw() stops hb + FUA-stamps own slot.
  - Monitor: WITHDRAWN stamp on a monitored+live slot → FUA confirm → instant fire_dead
    (P163-WITHDRAW-SEEN). Recovery-pending slots polled; resolution (sector zeroed by elected
    replayer, or rejoin w/ new epoch) → FUA confirm → recovered_cb (P163-RECOVERED) runs the
    DEFERRED local purge.
  - v5_lease_expire_cb: fence → mark pending (P163-RECOVERY-PENDING, dup-guard) → election →
    elected queues replay; NO immediate purge. Re-election sweep over other pending slots
    (replayer-death re-arm). Legacy immediate-purge only as fallback (no disklock/slot/hook).
  - xfs foreign-replay work fn: replay FIRST, then mxfs_v5_dlm_recovery_complete (CAW purge +
    local dlm purge + clear pending + disklock_purge_node zeroes dead slot = cluster-wide
    done-flag) — bit cleared after (crash-safe re-election).
  - withdraw: removed mxfs_dlm_withdraw_release_all call; withdrawn node drops MASTER-serving
    TCP msgs (REQ/CONVERT/RELEASE); teardown release_all + release_slot + GOODBYE all gated
    !withdrawn (grants stay frozen for peers' recovery).
  - find_node_slot: in-memory pass no longer gated on monitored[] (fire_dead clears it before
    expire_cb); disk scan accepts WITHDRAWN stamp. (v0.11.103 — without this the pending path
    was skipped and legacy purge ran.)
- purge_node HB-clear accepts WITHDRAWN stamp (zeroing = done signal).

## Verification (tests/withdraw_recovery_test.sh — in tree, reusable)
Flow: creator=test6 populates 64 files; victim=test1 rm -rf mid-flight + dbg_dialloc_shutdown=1
(dirty trans_cancel → EFSCORRUPTED shutdown; xfs_io/GOINGDOWN ioctl ENOTTYs on this fork — use
the dbg param). PASS gates: stamp, seen, elected replay complete, deferred purges, NO dangling
dirents from 2 survivors, no survivor shutdowns, cluster writable.
**RESULT: PASS @16/tcp** — stamp 2ms after shutdown; 15/15 survivors saw in ~1.5s; test8 elected,
"Starting recovery" 61.85 → P163-RECOVERY-COMPLETE 66.77 (~5s freeze); P163-RECOVERED=14;
namespace fully consistent (replay applied all committed unlinks; listed=0 dangle=0);
P-LKTIMEOUT/-110 = 0 on sampled survivors. Also drc@16 PASS (101s) at 0.11.102 pre-fix-P2.

## Still open / notes
- Hard-death flavor (no stamp: VM kill) uses same deferred machinery via stale-HB window —
  exercised by crash_consistency in the rung re-runs; watch P163-RECOVERY-PENDING/COMPLETE there.
- PR fencing on tcm_loop is ADVISORY (P-PR-ADVISORY 1 key for N members) — fence returns true;
  real PR flavors (cawp/cawd rigs) must re-verify the fence-first ordering.
- dead-detect window on this rig: lease_timeout default 600000ms → disklock samples may be 300
  (600s) for CRASH deaths; withdraw stamp bypasses it. Consider tightening for prod defaults.
- drc create-wave still ignores write errors (test gap, noted in sess9-A memory).
- Next: drc@16 batches (Shape-1 P60-RDVGG verification + drc closure), then rung re-runs at one
  srcver, wider ladder.

---
name: ccloop-c7ee71c6-sess211-incident474-ledgered-476-selflatch-nearmiss
description: sess211: incident474 arms A+B LEDGERED (30 open); 0.11.476 fence self-latch probe deployed; board 27/27 PASS; test31 near-miss captured (BUF-item AIL…
metadata:
  type: project
---

# sess211 — incident474 ledgered, self-latching probe live, near-miss captured

## Ledger
- D-NOINO-RELFENCE-AIL-FREEZE-474 (arm A, critical) and
  D-WITHDRAWN-NODE-CASCADE-NONCONTAINMENT-474 (arm B, critical) added to
  OPEN_DEFECTS.json → 30 open of 75, 19 critical. Full mechanism text in the
  entries. Evidence durable at tests/evidence/incident474/*.klog.gz (was
  volatile /tmp scratchpad).

## Builds
- 0.11.475: mxfs_noino_drain_fence self-latches mxfs_ailstuck_probe at
  stall==2 (xfs_mxfs_dlm.c ~19348) so P129-CLSKIP names the frozen item's
  skip reason IN-INCIDENT; plus manual `ailstuck_probe` module param
  (module_param_cb in pal/linux/xfs_aops.c).
- 0.11.476 (sv E58A57846DFC3885FDCA106, DEPLOYED 32/caw): odumps stack-dump
  budget made per-arm-event (mxfs_ailstuck_odumps + mxfs_ailstuck_probe_arm()
  inline in xfs_trans_priv.h; .h change → make clean).

## Measured baseline (important)
Pre-arming the probe fleet-wide is COUNTERPRODUCTIVE: healthy 32/caw
rsync_paired laps fire ALL FOUR P129-CLSKIP reasons ~100+/lap/node
(IFLUSH_RAN, ILOCK_NOWAIT_FAIL, PINNED, RECLAIM_OR_FLUSHING) — pre-arming
burns ratelimit buckets and the 3 sched_show_task dumps before any wedge.
Rely on the stall==2 self-latch; leave the param 0.

## Rig
Re-prepped from all-32-withdrawn (prep_cluster 114s w/ 13 power-cycles, then
73-77s clean). Full board on .476: 27/27 real PASS. 12+6 rsync laps PASS.

## Near-miss (NOT yet analyzed — next session step 1)
test31 16:48:22-24Z: two fences (inos 53491136/33554595) hit stall==2;
P-AILMIN shows AIL min frozen at an inode-CLUSTER BUF item lsn=0x1000028d9
daddr=19377256 bflags=0x500020 pin=0 — a BUF item, unlike the incident's
INODE item. Both recovered. Probe self-latched → post-16:48:22 P129-CLSKIP
lines on test31 exist and are unread.

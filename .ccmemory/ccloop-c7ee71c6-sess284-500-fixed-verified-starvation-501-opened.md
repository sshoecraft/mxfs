---
name: ccloop-c7ee71c6-sess284-500-fixed-verified-starvation-501-opened
description: sess284: D-500 agwait-relock convoy FIXED AND VERIFIED 0.11.501 (xfs_lock_inodes Phase A/B); dlm_fairness still red = NEW hot-dir EX starvation D-501
metadata:
  type: project
---

# sess284 — D-500 closed, D-501 opened

## D-AGWAIT-RELOCK-ILOCK-HOLDWAIT-CONVOY-500: FIXED AND VERIFIED
- Fix (0.11.501 sv E46174A71A5B5EA983AEA6D): mxfs_trans_agwait_handoff relock
  loop replaced plain blocking per-inode xfs_ilock with FIX-L3 Phase A/B —
  `xfs_lock_inodes(ips, nips, XFS_ILOCK_EXCL)` for nips>=2 (all cross-node DLM
  grants first, ascending, NO rwsems held; rwsems nowait-only), plain xfs_ilock
  for nips==1, `xfs_trans_ijoin` only after the whole set is locked.
- GPT RULE-5 review accepted with 2 gates, both verified: (1) never call
  xfs_lock_inodes with <2 inodes (asserts 2..5; XFS_DEFER_OPS_NR_INODES=5);
  (2) shutdown postcondition — ilock_begin refuses on shutdown
  (P-SHUTDOWN-FENCE) but Phase B still takes every rwsem; caller's one
  xfs_iunlock/inode stays balanced (P71 tolerates unpaired end). GPT also
  flagged (pre-existing, not this patch): mixed inode-DLM/AG-DLM class-order
  cycles are unproven-absent fleet-wide — architectural audit candidate.
- Verification: dlm_fairness 32/caw PASS 32/32 (28s/30s) with cause exercised —
  P271-AGWAIT-PREACQ on test14 at 23.4s INTO the passing run (wall-mapped).
  Convoy signature absent in ALL 4 post-fix runs: no P-ACQ-STUCK, no
  AG-AIL-STALL, no D-state fleet, sync <0.1s, max P139-LOCKTOTAL 6.4s (was 480s).
- Trap: pre-fix 480s stalls remain in node dmesg (prep does not reboot) —
  filter by uptime/wall mapping before attributing.

## D-DLMFAIRNESS-32CAW-HOTDIR-EX-STARVATION-501: NEW (critical, OPEN)
- dlm_fairness 32/caw fails 30s budget 3-of-4 on 0.11.501: fast nodes 16
  rounds in 7-14s, starved nodes ~25s to FIRST round (test1 r=1 @25.68s, 4/16
  at kill). Max single acquisition wait 6.4s fleet-wide → starvation is
  REPEATED consecutive losses, not one long wait. Aggregate ~22ms/op vs
  ~19.5ms needed. 6.4s ≈ 5s MXFS_CAW_YIELD_TIMEOUT_MS stale-clear + backoff.
- H1 (uninstrumented): releaser's yield_to "round-robin" EX-waiter nomination
  (dlm/dlm_caw.c ~5496-5560 helpers, ~6139+ releaser side, header ~75-132
  "snapshot BATCH ticket") is biased or re-snapshots the same batch; starved
  nodes only enter via the 5s stale-clear. NOT the sess130 upgrader-livelock.
- Instrumentation added: tests/suite/dlm_fairness.sh writes per-phase trace to
  node-local /tmp/dlm_fairness_progress (found the starvation; keep).
- Next: measure per-node grant-winner counts + yield_to nomination values on
  the hot dir slot during one run; falsify/prove cursor bias; then RULE-5.

## Board state
- 0.11.501 prepped clean 32/caw (prep 73s). dlm_membership/dlm_scaling BLOCKED
  cells (old convoy node-faults) need re-run on .501; board chunks B-D unrun.
- Ledger: 36 open (25 critical) after closing D-500 and opening D-501.

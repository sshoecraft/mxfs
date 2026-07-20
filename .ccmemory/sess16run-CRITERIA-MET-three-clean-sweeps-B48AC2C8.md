---
name: sess16run-CRITERIA-MET-three-clean-sweeps-B48AC2C8
description: sess16 CRITERIA MET: build B48AC2C8 = 3 consecutive fresh-boot sweeps of 1/2/4/8-node tcp, 12 runs, 0 FAIL (16+17+17+17 ×3). Evidence tests/results_s…
metadata:
  type: project
---

# CRITERIA MET — "1/2/4/8 node tcp dlm test working 100%"

## Final build: B48AC2C8629294ADF396154
= 0F1666F1 (sess15: FIX-H3 + P15I + FIX-I + FIX-J2)
+ FIX-K   (lockless mxfs_dlm_is_single_node — dlm/dlm.c)
+ P16-ILOCKED probe (xfs_trans_ail.c AG-AIL-STALL ilocked= field)
+ FIX-L3  (Phase-A all-members-ascending DLM pre-acquire in
           xfs_lock_inodes + xfs_lock_two_inodes — xfs/xfs_inode.c,
           helpers mxfs_setlock_dlm_mode / mxfs_iunlock_rwsems_raw)

## Evidence (third-party verifiable)
- 12 consecutive suite_iter runs (each = full VM recycle, fresh mkfs,
  full battery incl. fencing/netpartition/crash/soak/tds), ALL on
  B48AC2C8, ALL zero FAIL:
  1/tcp 16/16 ×3, 2/tcp 17/17 ×3, 4/tcp 17/17 ×3, 8/tcp 17/17 ×3.
- criteria.json columns 1/2/4/8 tcp: 100% PASS, 0 PENDING/SKIPPED.
- Logs + criteria snapshot preserved: tests/results_sess16_streak/
  (iter{1,2,4,8}_M{1,2,3}.log + criteria_snapshot.json).
- Marker written: .ccloop/runs/a9a03929-.../criteria-met = YES.

## The two sess16 roots (details in sess16run-FIXK-* / sess16run-FIXL2-* /
## sess16run-FIXL3-*)
1. FIX-K: is_single_node's global mutex × 2.27M calls/leg = the paired
   ~5% residual → 1/tcp column complete.
2. FIX-L3: set-lock functions blocked cross-node holding member rwsems
   (k1 ABBA: dir conversion vs AG-4 drain vs peer alloc).  L1 (bare
   begin/end retry) livelocked; L2 (dirs-first) convoyed drc at 8n;
   L3 (ascending-all, held, rwsems nowait-after) = clean.

## If a future flake appears
tds/drc wedge attribution is one dmesg grep away: P67-INSTR
AG-AIL-STALL ... ilocked= (held-ILOCK flush block) + P129-CLSKIP
why=ILOCK_NOWAIT_FAIL owner-comm.  r21-flavor (REL-ABORT starvation)
remains theoretically possible under extreme same-ino churn — distinct
from the k1 ABBA; evidence template in sess16run-FIXL2-*.

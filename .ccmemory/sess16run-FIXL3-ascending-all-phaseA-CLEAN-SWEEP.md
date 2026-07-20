---
name: sess16run-FIXL3-ascending-all-phaseA-CLEAN-SWEEP
description: sess16 FIX-L3 (B48AC2C8): Phase A = ALL set members ascending (not dirs-first). CLEAN SWEEP 1/2/4/8 tcp (16+17+17+17). L2 dirs-first convoyed drc at…
metadata:
  type: project
---

# FIX-L3 — final shape of the set-lock fix + first clean sweep

## Evolution (do not regress)
- L1 (399BEA9F, REVERTED): DLM-try + bare begin/end + retry → grant
  ping-pong livelock (ilock_end at 0 holders fires peer BAST inline,
  forfeits instantly).  2/tcp: rm 184s rc=-110 shutdown cascade.
- L2 (CC3B3372, REVERTED): Phase A for EX-DIRS only, before rwsems.
  Fixed the k1 ABBA but created a CONVOY: removes held the shared dir EX
  across their cross-node CHILD acquires → 8/tcp drc round-12 create
  phase 200s+ → 0/8 timeout (2/tcp flavor: readdir=197 exp=200
  undercount).  fence_during_write 0/8 followed in the same run.
- **L3 (B48AC2C8, KEEP)**: Phase A = EVERY set member, ascending ino,
  mode from mxfs_setlock_dlm_mode (exact xfs_ilock mapping: EXCL→EX else
  PR; 0 when no m_mxfs_dlm).  This reproduces the HISTORICAL per-
  xfs_ilock DLM acquisition order (child grant settles BEFORE the dir
  grant is taken when child<dir) minus the rwsem-held-across-DLM-wait
  hazard.  Phase B: pre-held members take rwsems xfs_ilock_nowait-only;
  backoff releases rwsems RAW via new mxfs_iunlock_rwsems_raw (keeps the
  DLM hold + mxfs_ilk_note_unlock).  Helpers above xfs_lock_inodes in
  xfs/xfs_inode.c.  Applied to BOTH xfs_lock_inodes and
  xfs_lock_two_inodes (two_inodes: pre0 nowait-spin, pre1 nowait+raw
  backoff; middle AIL arm reachable only in no-DLM config).

## Validation on B48AC2C8 (all fresh-boot suite_iter runs)
- 2/tcp M1 17/17, 8/tcp M1 17/17 (drc + fence + tds ALL PASS), 4/tcp M1
  17/17, 1/tcp M1 16/16 (paired 101%, fio worst_write 100%).
- = FIRST full four-column clean sweep of the run.  Streak accumulation
  next (target ≥3 consecutive sweeps before writing the criteria marker).

## Where the k1-wedge probes still sit (armed, zero-cost)
- P16-ILOCKED `ilocked=` field in P67-INSTR AG-AIL-STALL (xfs_trans_ail.c).
- P129-CLSKIP why=ILOCK_NOWAIT_FAIL prints rwsem owner comm (iflush skip).
If drc/tds ever wedge again, those two lines attribute it in one shot.

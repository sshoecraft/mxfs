---
name: ccloop4dd7-sess4-C-ROOT-iolock-dlm-order-inversion
description: sess4 root #4 PROVEN+FIXED v0.11.62: xfs_ilock IOLOCK took DLM admission BEFORE i_rwsem → phantom admissions of parked writers wedged demote (b58r1/b…
metadata:
  type: project
tags: [ccloop-4dd7, root-cause, lock-order, iolock, deadlock]
---

# ccloop-4dd7 sess4 root #4 — IOLOCK DLM-before-rwsem inversion (PROVEN b61r6, FIXED v0.11.62 = ECD8EA42)

## Proof (b61r6, via the v0.11.59 P36-EXH-STACK holder instrument)
- Stall recurrence of the b58r1 family: test1 stuck EX(131) rm, test2 stuck 135, dual -110 at 17:47:45
  (~184s after churn start; round effectively dead the whole time).
- P36-EXH-STACK on test1 (strikes=200, 1.2s into refusal): ino=135 exh_pid=101418 bash — task state D at
  `xfs_file_buffered_write → xfs_ilock → rwsem_down_write_slowpath`: **holding the DLM EX(135) admission
  while PARKED on the i_rwsem**. ex=2, pr=0; the rwsem HOLDER carried NO admission (VFS-entered path —
  setattr/truncate class — which takes i_rwsem first, DLM later).
- P36-EXH-STACK on test2: ino=131 exh_pid=104212 rm at `xfs_remove → xfs_trans_alloc_dir →
  xfs_lock_two_inodes → mxfs_dlm_ilock_begin (schedule_timeout)` — Phase-A holder of ip0=131's admission
  waiting for ip1 (cross-node edge to test1's wedged 135).
- Local 3-party wedge on test1: BAST(135) closes fast path → rwsem holder's DLM ILOCK acquire goes
  slow-path behind the demote → demote waits ex_holders==0 → ex_holders includes the PARKED writers'
  phantom admissions → nobody progresses → peers -110 → dual shutdown.

## Root
xfs_ilock() took mxfs_dlm_ilock_begin (DLM admission) BEFORE down_write(i_rwsem) for IOLOCK classes
("distributed lock before local semaphore"), while VFS-entered paths are inherently i_rwsem→DLM.
Two orders for the same pair = deadlock the moment the fast path closes under BAST.

## FIX (v0.11.62)
xfs_inode.c: xfs_ilock takes the IOLOCK i_rwsem BEFORE mxfs_dlm_ilock_begin (global order now
i_rwsem → DLM → mmap/ilock semaphores everywhere); xfs_ilock_nowait mirrored (rwsem trylock first,
undo-chain relabeled: mmap-fail → undo dlm+rwsem, dlm-fail → undo rwsem). xfs_iunlock release order
already symmetric (rwsem up before dlm end). Safe: flushers (iflush/xfsaild) take ILOCK never i_rwsem,
so a cross-node DLM wait under i_rwsem blocks only same-file ops that would queue anyway.

## Residual on task #6
b58r1's exact holder stacks were never captured (pre-instrument). Consistent with this root OR a
Phase-A-holder-blocked-on-ILOCK-mrlock shape; P36-EXH-STACK stays armed — any recurrence self-names.

## State
Ladder 5/5 CLEAN b61r1-r5 (v0.11.61); deadshell 8/8; full 2/tcp suite 19/19 PASS (run_ids
20260724T1735xx). b61r6 = this stall → ladder resets at b62r1 on v0.11.62.

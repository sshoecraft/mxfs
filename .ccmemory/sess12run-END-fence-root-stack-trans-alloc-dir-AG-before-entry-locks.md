---
name: sess12run-END-fence-root-stack-trans-alloc-dir-AG-before-entry-locks
description: sess12 END: fence starve root STACK CAPTURED (iter2 r16): rm HOLDS AG-0 while waiting dir-EX inside xfs_remove→xfs_trans_alloc_dir→xfs_lock_two_inode…
metadata:
  type: project
---

# sess12 END — the fence AG→dir edge is in the REMOVE path's trans-alloc, stacks captured

## DECISIVE (ladder iter2 = r16, build 5BE16AA5, artifact /tmp/run_fence_during_write_20260704T032716Z)
- t2+t4 rc=-110 ag=0 defer_finish shutdowns again (fence 1/4, netpartition 2/4, tds 0/4 collateral).
- **P12-HOLDERTASK ag=0 pid=13873 comm=rm (test1)** — the stamped AG-0 holder — stack (repeated 1/s, state:S in mxfs_pal_cond_timedwait):
  `xfs_vn_unlink → xfs_remove → xfs_trans_alloc_dir → xfs_lock_two_inodes → xfs_ilock → mxfs_dlm_ilock_begin → mxfs_v5_dlm_inode_lock → mxfs_dlm_lock_retries (waiting ino=540053 EX)`
- So the rm ACQUIRED AG-0 EX (holders 0→1 stamp = this pid) BEFORE/AT xfs_trans_alloc_dir, and only THEN blocks acquiring the two entry inode locks → AG→dir hold-and-wait; peer rm (dir→AG in defer_finish) completes the 60s cycle. Same-shape P36-STACK on test3 (ino=540053 EX comm=rm) — multiple waiters behind the same dir.
- ino=540053 = the fence hot dir of that run. t1's rm = fence hot-file rm or dir_reuse cleanup.

## NEXT SESSION — the fix target
1. Read `xfs_trans_alloc_dir` (fork: xfs/xfs_trans.c or xfs_inode.c) + any mxfs overlay pre-acquiring the AG there (grep t_mxfs_ag_unlocks / mxfs_ag_dlm_lock callers reachable from it). Find EXACTLY where AG-0 EX is taken before xfs_lock_two_inodes in xfs_remove. Candidates: mxfs hook in trans reservation; sync inodegc/xfs_inactive of the PREVIOUS unlink leaving a grant attached to the task; trans_dup migration.
2. Apply the FIX3 treatment: order entry locks BEFORE the AG acquire (or drop/retake), preserving RWSEM semantics. One fix, then ladder again.
3. The r5 evidence (holders=1 frozen 60s, readopt=0) matches this: ONE rm holding AG-0 in one frozen transaction slot while waiting the dir.

## State at relay
- Build 5BE16AA5 = FIX-A (pin-aware release abort — KEEP, proven hole) + FIX-B (iget-miss cluster reload — KEEP, dlm_scaling face gone since) + full probe stack (P12-*, P36-STACK, DLMTR ring, drc raw-block capture).
- Ladder on 5BE16AA5: r14 17/17, r15 17/17, r16 14/17 (this fence face), iter3/4 still running at relay (check /tmp/suite_ladder_*.log + /tmp/suite_iter_out_*.log; ladder pid may still be live — check `pgrep -f suite_ladder` before starting new runs, kill leftovers + recycle VMs after shutdowns).
- 4/tcp remaining blocker = ONLY this remove-path AG→dir edge. dir_reuse hasn't failed since FIX-A (r11-r16: no drc FAIL). 1/2/8 columns untouched this session (need re-run on final build; 8/tcp had dlm_scaling+tds FAILs on Jul 3 pre-FIX2/3/A/B).
- Probe harvests: /tmp/suite_iter_probes_*.log per iteration (P12-READOPT normal ≤ n=6/112ms).
- Gotcha reminders: virsh-recycle all 4 after any shutdown (rmmod wedges); don't edit tests/suite_iter.sh while an instance runs; artifacts only persist for FAILed tests; fence/netpartition/tds FAILs after a fence shutdown are one root.

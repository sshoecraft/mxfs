---
name: ccloop4dd7-sess3-A-difree-estale-and-wedge-forensics
description: sess3: difree-ESTALE adopt fix (v0.11.54, round5 ino134 proven); b54r1 liveness wedge = leaked buf lock + leaked ACQUIRING; v0.11.55 self-naming prob…
metadata:
  type: project
tags: [ccloop-4dd7, dialloc-corruption, dlm-liveness, buffer-lock-leak]
---

# ccloop-4dd7 sess3 state (mid-session checkpoint)

## Fix landed + PROVEN-ROOT (v0.11.54 = 2B8E86CE):
**Round-5 ino 134 double-inactivation**: peer (test1) completed unlink+ifree; test2's mirror adopted
nlink=0 from disk (P9-NLEDGE from_disk, rmcnt=0, local_unlink=0) and VFS re-inactivated → P-DIFREE-DBL
(continued! freecount 58→59 desync) → empty-bucket P71 → -117 dirty → shutdown. Arm-2 missed because
`xfs_inode_on_unlinked_list()` is per-node in-core (never set for adopted mirrors).
FIX: xfs_difree_inobt DBL point returns -ESTALE in multinode (tx still clean — only lookups ran);
xfs_inactive_ifree converts -ESTALE → adopted-peer-free clean skip (cancel releases ijoin'd ILOCK; clear
membership; error=0). ESTALE unambiguous in the ifree graph. NEEDS VERIFY (never fired live yet).

## b54r1 (v0.11.54 round 1) liveness escalation — TWO chained leaks, live-forensicated:
- test2 rmdir EX(131) starved 184s (holder=test1 PR, per-second BASTs ignored) → -110 → dirty cancel at
  mxfs_dlm_ilock_begin:22917 → shutdown.
- test1: dir 131 stuck ISTATE_ACQUIRING (state=4) mode=PR, ex=0 pr=0, **i_dlm_acq_inflight presumed 0** —
  every BAST deferred via bast_during_acq to an acquire-completion that no longer exists. LEAKED ACQUIRING.
  Invariant: live slow-path acquirer always has inflight>=1 (both under i_dlm_lock) ⇒ ACQUIRING+inflight==0
  = leak, deterministically.
- W1 (the deeper root): inode-cluster buffer daddr 128 (inos 128-159) left LOCKED, flags 0x32
  (WRITE|ASYNC|DONE = write bio in flight, completion never ran). Exhaustive /proc/*/stack sweep: NO live
  holder. rmdir 85980 blocked on it inside do_rmdir's dput (this kernel dputs BEFORE inode_unlock(parent))
  → holds parent i_rwsem → node-wide convoy (all workers D in VFS waits). Flush kworker also blocked.
  Prime suspect: custom partial/coresident cluster write path (P56 family, mxfs_submit_partial_inode_write
  in pal/linux/xfs_buf.c ~2960-3315, chained bios) — or lost ioend.
- journald wraps in ~100s at full probe volume (RuntimeMaxUse=400M): capture logs IMMEDIATELY; test1's
  pre-13:23 window was lost in round 5.

## v0.11.55 = 52205D4F (BUILT, deploying next): self-naming instruments
1. P-BUFLOCK-STUCK: xfs_buf_lock down_timeout(30s) loop → prints daddr/ops/flags/hold/pin/err/
   **b_lock_ip(%pS)**/ioend_seen/relse_seen/sync_waiters/evring + waiter. No behavior change.
2. ACQUIRING-setter stamp (i_dlm_acq_pid/comm/set_ns/strikes in xfs_inode.h, stamped at the single set
   site mxfs_dlm_ilock_begin ~22611, init at mxfs inode-init ~25207).
3. P-ACQ-ORPHAN-RECLAIM in bast_notify ACQUIRING branch: inflight==0 && ++strikes>=8 → print setter →
   state=DEMOTING → igrab+queue bast_work (bastq_src=4) → peer unblocks. Mirrors P-DEMWAIT-REDRIVE.

## Ladder state: counter resets at v0.11.55. Need 5 consecutive clean fresh-FS rounds
(prep_cluster before EVERY round; agi_wedge_repro.sh 180 24; then grep sig + mount check per node,
capture logs immediately). Then deadshell_repro 8/8, full ./run.sh 2 tcp, task #3 open items
(incl. pve2 flush_workqueue wedge on the PVE pair — user asked; current work is all on test1/test2 VMs).

## Key file/line anchors: DBL site xfs_ialloc.c~2731; ifree intercept xfs_inode.c~3156 (after xfs_ifree);
bast_notify ACQUIRING branch xfs_mxfs_dlm.c~16077; entry wait loop ~22395 (P73/P-DEMWAIT-REDRIVE arms);
completion block ~23214 (ACQUIRING→CACHED/BAST); acq_inflight sites: ++22606, --22843/22856/22890/22914/23313.

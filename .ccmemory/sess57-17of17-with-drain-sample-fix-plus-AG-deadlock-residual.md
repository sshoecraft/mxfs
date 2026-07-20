---
name: sess57-17of17-with-drain-sample-fix-plus-AG-deadlock-residual
description: sess57: build DDF775DD (drain-sample-under-ilock fix) passed clean ./run.sh 2 tcp = 17/17, 0 shutdowns. Reliability streak + AG-DLM-deadlock(trans_ca…
metadata:
  type: project
---

## sess57 — clean 17/17 on build DDF775DDF8E3198DEA4254A; criterion NOT yet declared (need reliability streak)

### THE FIX THIS SESSION (KEEP, build DDF775DD): drain-loop in_ail/pinned sample-UNDER-ilock
`xfs_mxfs_dlm.c` bast_process dir-release drain loop (~5044): the loop sampled `in_ail`/`pinned` BEFORE the blocking `mxfs_drain_ilock_read` acquire. If an `mv` held ILOCK_EXCL for its rename and committed (PINs inode in CIL, releases ILOCK) WHILE the drain spun on the acquire, the loop used the stale pre-commit CLEAN value → broke "clean" → released EX with the removal stranded in AIL → P119-NONEX in_ail=1 → P-CLMERGE overlaid stale disk → RESURRECTION (the sess56 ROOT). FIX: sample in_ail/pinned AFTER the acquire (fresh, under the lock). Added proof-probes P57-DRAIN-RACE-CAUGHT (drain loop) + P57-PREUNLOCK-DIRTY (right before mxfs_v5_dlm_inode_unlock). This is GPT's sess55-ranked #1 "mandatory durable-drain-before-EX→NL/PR demote" — making the durable-drain actually work closes all 3 reconciliation faces (P119, merge, P34D-reload) at root.

### RESULT: full ./run.sh 2 tcp = 17/17 PASS, 0 FAIL, 0 shutdown/corruption markers on BOTH nodes. dlm_fairness/dir_reuse_coherency/tcp_dlm_scaling ALL PASS. (run.sh bg exit code 1 was spurious; log = `=== done: ran=17 pending=0`.)

### CAVEAT: my fix did NOT fire this run (P57 probes=0, P-CLMERGE=0) — no resurrection occurred to exercise it. So this 17/17 may be luck (prior sessions: 17/17 then 16/17). Need a RELIABILITY STREAK (sess53 target ≥6-8 consecutive clean 17/17) before claiming the criterion.

### RESIDUAL face (b) — AG-DLM cross-node DEADLOCK → trans_cancel:1061 shutdown (sess53-documented criterion failure face, NOT just repro):
Reproduced reliably via `bash tests/tcp/repro_rename_drain.sh 150 10` (deadlocks ~iter 6 after 5 clean iters). MECHANISM: node1 holds dir-DLM-EX (ino 132) + spins 28x on AG0-DLM-EX (P36-RETRY ino=0 type=3) → timeout rc=-110; node2 holds AG0 + waits dir-132 → timeout. Cross-node hold-and-wait (create=AG-then-dir, remove=dir-then-AG; dir lock CACHED across ops). The AG0 lock is needed by xfs_droplink→xfs_iunlink (AGI unlinked list) AFTER xfs_dir_remove_child already DIRTIED the trans → timeout → xfs_trans_cancel on dirty trans = Corruption(0x8) shutdown. xfs_droplink is libxfs/xfs_inode_util.c:798 (xfs_iunlink). xfs_remove pre-dirty region: xfs_inode.c ~3676-3727.
FIX DIRECTION (not yet done): pre-acquire ip's AG DLM lock in xfs_remove BEFORE dirtying (like xfs_ifree at xfs_inode.c:2505-2514 which clean-cancels on AG-lock fail); on deadlock, clean-abort + retry loop so node1 releases dir-132 (deferred BAST fires after iunlock) → node2 proceeds → node1 retries + succeeds (NOT just leak). Heavy in suite (single 150-round pass usually OK); rare but real over many runs.

### REPRO/RUN MECHANICS (this session, working): reboot `virsh -c qemu:///system destroy/start test1 test2`; prep `MXFS_PASS=/tmp/.mxfs_pass bash tests/setup/reset2_tcp.sh test1 test2` (PLAIN, no MXFS_EXTRA_MODARGS); suite `timeout 565 ./run.sh 2 tcp` (set Bash tool timeout=595000 to run FOREGROUND — else it auto-backgrounds; output to a logfile). dmesg shutdown check: grep 'Shutting down|Corruption of in-memory|trans_cancel'. Marker NOT written.

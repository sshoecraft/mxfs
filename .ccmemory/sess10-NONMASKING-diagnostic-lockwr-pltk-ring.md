---
name: sess10-NONMASKING-diagnostic-lockwr-pltk-ring
description: sess10: the NON-MASKING diagnostic to beat the Heisenbug is ALREADY BUILT — lockwr=1 lock-free P-LKT ring + /sys/.../lktdump post-mortem dump. Exact…
metadata:
  type: project
---

## THE way to instrument the 2/tcp dir lost-update WITHOUT masking it (printk-based dirwr=1/instr=1 MASK the race; this does NOT). For [[sess10-SYNTHESIS-handoff-and-final-target]].

## READY-TO-USE (in-tree): the lock-free P-LKT ring (dlm/dlm.c ~83-161, xfs_mxfs_dlm.c:11383).
- `mxfs.lockwr=1` (module param `lockwr`): records EVERY master lock-table lifecycle event {seq, ts_ms, action, ino, owner, mode} into a 16384-entry lock-free ring. NO hot-path printk -> does NOT perturb timing -> does NOT hide the race. Actions seen: GRANT-LOCAL, GRANT-REMOTE, REAFFIRM-REMOTE, RELEASE (line 1418), + dg P-DOUBLEGRANT detector still fires on a real double-grant.
- DUMP post-mortem: write the parent-dir inode number to `/sys/module/mxfs/parameters/lktdump` (0 = all) on EACH node -> ring emitted to dmesg as `P-LKT seq=.. ts_ms=.. <action> ino=.. owner=.. mode=..`. Dump AFTER the failure (the comment: "Dumping AFTER the race avoids the printk perturbation that hides the double-grant when tracing live").

## EXACT PROCEDURE (next session, FOREGROUND per [[feedback-never-background-wait-poll]]):
1. Build + deploy current tree. Prep with `MXFS_EXTRA_MODARGS='lockwr=1'` (run.sh passes it via prep_node).
2. Run `./run.sh 2 tcp` FOREGROUND (full suite ~6min, fits one foreground call) until tcp_dlm_scaling FAILs (`tds shared dir drained got=1`).
3. Get the `.tcp_dlm_scaling` dir inode number: on a node, `stat -c %i /mnt/shared/.tcp_dlm_scaling` (it persists; or grab from the test's leftover path).
4. On BOTH test1+test2: `echo <ino> > /sys/module/mxfs/parameters/lktdump`; then `dmesg | grep P-LKT`.
5. READ THE TIMELINE: is the grant/release sequence on that dir ino STRICTLY ALTERNATING across owners (clean handoff) or OVERLAPPING (GRANT owner=A while owner=B still GRANTED with no intervening RELEASE = the double-grant)? Correlate ts_ms across nodes.

## INTERPRETATION:
- If P-LKT shows a real DLM double-grant / missing RELEASE -> the bug is in the TCP DLM grant/release path (dlm/dlm.c) despite the gen-token fix -> fix there.
- If P-LKT shows a CLEAN alternating DLM timeline (likely — P-DOUBLEGRANT historically 0) -> the DLM layer is correct and the bug is the XFS-CACHE layer: a node serves a dir read/modify on a stale CACHED grant WITHOUT re-entering the DLM. Then BUILD AN ANALOGOUS XFS-LAYER LOCK-FREE RING (mirror the P-LKT design — lock-free, no hot-path printk, dump via a new param) recording every dir PR/EX fast-path SERVE {ino, req_mode, i_dlm_mode, i_dlm_state, i_dlm_dir_gen, i_dlm_dir_loaded_gen, ts} at the dir-strict-gate else-block (~6594). Dump after failure -> shows the failing node serving a stale cached grant (i_dlm_mode!=NL, no DLM acquire) while the peer's committed change is missing. THAT pinpoints the exact stale-serve.

## This is the highest-value next action — it replaces guesswork/static-analysis (which hit diminishing returns sess10) with a non-masking measurement of the actual handoff. Baseline 5EC1F0BF deployed.

---
name: sess17run-HANDOFF2-dgshadowLRU-keep-8tcp-residual-is-EXcontention-slowness
description: sess17(ccloop) HANDOFF2: KEEP build 544A912E (fork-adopt + dg_shadow LRU). 1/2 tcp full PASS, 4/tcp focused PASS, 8/tcp data-loss FIXED. 8/tcp residu…
metadata:
  type: project
---

## sess17 (ccloop) HANDOFF2 — major progress, 8/tcp residual reframed

### KEEP build: 544A912E9356E96A39F24E2 (in /src/mxfs/mxfs.ko)
Two fixes, both validated safe:
1. **fork-adopt** (xfs_mxfs_dlm.c ~11027/11295/11331/11434): fast-path dir reload uses post_release=dir_ex_handoff, true only on reliable cross-node handoff. [[sess17run-FIX-forkadopt-handoff-round1-fixed-round5-residual]]
2. **dg_shadow LRU** (dlm/dlm.c, DG_SHADOW_N=512 + last_grant_seq LRU eviction): makes the cross-node handoff/epoch RELIABLE (the hot dir inode's shadow slot is never recycled by the ~800 file-inode grants/round). [[sess17run-MILESTONE-dgshadow-LRU-fixes-dataloss-newresidual-timeout-leaf]]

### CRITERION STATUS (full ./run.sh <N> tcp):
- **1/tcp = 16/16 PASS ✅**
- **2/tcp = 17/17 PASS ✅** (verified on the LRU build — no regression)
- 4/tcp: focused dir_reuse PASS 4/4; FULL suite has in-suite contamination of dir_reuse (separate, [[sess17run-CRITICAL-two-distinct-blockers-8tcp-focused-vs-4tcp-insuite]]). Re-run full 4/tcp on 544A912E to recheck.
- 8/tcp: dir_reuse DATA-LOSS ELIMINATED (RDMISS=0, was 799/800 every round across 100+ sessions). Residual = SLOWNESS, not loss.

### 8/tcp residual REFRAMED: EX-contention slowness (tractable perf, not durable loss)
Focused 8/tcp dir_reuse: RDMISS=0 on all nodes, but FAILS via **P36-RETRY storm on ino=131** (8 nodes serialize on the ONE shared dir EX; reliable-handoff reload extends each EX hold → long retry queue → hard rc=-110 acquire timeouts). ~67s/round (reached round 6 in ~400s) = RULE-0 slowness fail. Timeouts/leaf-holes concentrate on the hot-dir MASTER nodes (test1/test2). leaf-hash holes (P21H) persist (dir_leaf_rebuild=1 fires P26-REBUILD-OK but doesn't fully close them; likely secondary to the slowness / barrier break).

### NEXT (perf, not correctness): reduce the per-handoff cost that amplifies dir-EX contention at 8 nodes.
- PROFILE first (RULE 4): P34-ACQ-SLOW dur_ms (acquire+reload cost) and P51-REL drain_ms per handoff — find the dominant cost (FUA dinode read in mxfs_dlm_reload_inode? release-drain FUA writes?).
- Candidate fixes: (a) make the fast-path reload LIGHTER — skip full xfs_inode_from_disk when di_nextents unchanged (only block content changed → drain_evict/lazy read suffices); (b) tune mht (inode_mht_ms, default 300) now that handoff is reliable; (c) reduce release-drain cost. Goal: dir-EX cycles fast enough that 8 nodes don't queue into 120s timeouts.
- Do NOT revert the LRU/fork-adopt fixes (they eliminated the data loss). Do NOT re-try per-modify epoch invalidation (timeouts) or acquire-side bulk evict (drops work).

Reboot ALL nodes clean (virsh destroy+start) between runs. DRC_STREAM=1 for NFS capture. Criterion NOT met; marker NOT written.</body>

---
name: sess18-foldtp-merge-no-shutdown-BREAKTHROUGH-perf-wall
description: sess18 BREAKTHROUGH: fold-into-create-tp block-dir merge (build AA741B4E, mxfs_dir_merge_peer_into_tp) does NOT shut down (avoids v1/v2 extra DLM acq…
metadata:
  type: project
---

## sess18 (ccloop 8ddb16a2) — fold-into-create-tp block-dir union-merge: NO SHUTDOWN (breakthrough vs v1/v2), but PERF wall.

## WHAT WAS BUILT (build AA741B4E, source committed in tree, dir_merge default 0):
- NEW `mxfs_dir_merge_peer_into_tp(tp, dp, max_ents)` in xfs/xfs_mxfs_dlm.c (after mxfs_dir_merge_peer_blocks). Snapshots peer's durable dir DATA blocks from the LUN (caller holds ILOCK_EXCL — NO ilock taken), then xfs_dir_lookup+xfs_dir_createname re-adds ≤max_ents missing peer dirents INTO THE CALLER'S tp. Gen-gate: returns early unless `i_dlm_dir_evicted_incarn != i_generation || i_dlm_dir_gen != i_dlm_dir_evicted_gen` (= the 1374 refresh kept an undestaged/stale block = merge needed).
- WIRED in xfs_create (xfs/xfs_inode.c): call at line ~1571, immediately AFTER `xfs_trans_ijoin(tp,dp,0)` and BEFORE `xfs_dir_create_child`. dp ILOCK_EXCL held + ijoin'd + dir-EX grant CACHED → **NO new DLM acquire** (the v1/v2 killer). REMOVED the old pre-lock `mxfs_dir_merge_peer_blocks(dp)` call (it took the fatal extra acquire). resblks bumped by `MXFS_DIR_MERGE_MAX(=16) * XFS_DIRENTER_SPACE_RES` when dir_merge on (header: xfs_mxfs_dlm.h has the proto + extern + #define).

## RESULT — NO SHUTDOWN (the v1/v2 failure is GONE): probe ran iters with mounts RESPONSIVE, no shutdown/corrupt/hung_task/EDEADLK/rc=-110 anywhere. This PROVES folding into the create's existing grant avoids the dir-EX acquire-timeout force-shutdown that killed merge v1 (per-entry) and v2 (single-tenure pre-lock) [[sess18-merge-v2-single-tenure-REFUTED-dlm-timeout]]. Major architectural progress.

## BLOCKER NOW = PERF (RULE 0), not crash: probe iters 1-2 full 200/200 then iter 3 EMPTY (ssh 40s timeout) — intermittent, not uniform. Mount responsive when idle. ROOT: the merge does DISK I/O (snapshot plain-reads of dir blocks) WHILE HOLDING the create's dir-EX grant, lengthening the hot-dir critical section → cross-node EX-handoff starvation stalls (sess50 family) → 40s+ stalls = RULE 0 fail. First ungated version (F5F46A31) was worse (full-dir read every create); gen-gate (AA741B4E) helped (iters 1-2 fast) but stalls persist under contention. (A runtime dir_merge=1-vs-0 timing test was inconclusive — cluster had degraded to a slow state after many cycles.)

## FIX FOR NEXT ITERATION — SPLIT THE MERGE (avoid BOTH failure modes):
1. Phase 1 SNAPSHOT (disk reads) at PRE-LOCK in xfs_create (~line 1296, where mxfs_dlm_dir_modify_reload_prelock runs) — NO grant held, I/O does not extend any critical section. Stash peer dirents into a LOCAL array in xfs_create.
2. Phase 2 RE-ADD (no I/O — just xfs_dir_lookup+createname, fast) inside the create's tp at ~line 1571 (current wiring), consuming the stashed array. NO disk reads under the grant.
This keeps NO-extra-DLM-acquire (re-add uses create's grant) AND removes I/O from the critical section. Then RE-VALIDATE: (a) perf — cc_blockdir_probe completes 25 iters with NO empty/timeout; (b) CORRECTNESS — does it close the durable loss? (couldn't confirm this session — perf stalls masked it); (c) ./run.sh 2 tcp 16/16 x>=5; watch cache_coherency/zsl/rename.
- Alternative perf cut if still slow: snapshot ONLY in-core UNDESTAGED blocks' disk images (the actual clobber-risk blocks), not all blocks.

## STATE: cluster DEGRADED after many test cycles — RECOVER to baseline (virsh destroy+start both, prep dir_merge=0) before next work. Builds this session: B0C5862 (v2 single-tenure, refuted), F5F46A31 (foldtp ungated, slow), AA741B4E (foldtp gen-gated, no-shutdown but perf-stall). Baseline = 492C8EB7 behavior. Marker NOT written (durable loss still live; fix not yet perf-viable+correctness-confirmed). [[sess18-readside-ruled-out-writeside-clobber-confirmed]] [[sess17-CONFIRMED-staleflush-clobber-P17]]

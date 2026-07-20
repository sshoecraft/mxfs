---
name: sess17-merge-v1-REFUTED-dlm-shutdown
description: sess17 merge v1 REFUTED: per-entry fresh-txn ILOCK_EXCL at create prelock churns DLM inode acquires → fails → force-shutdown (xfs_mxfs_dlm.c:8128). M…
metadata:
  type: project
---

## sess17 — block-level union-merge IMPLEMENTATION v1 REFUTED (build 492C8EB73ACA12A99A2992A, dir_merge=1).

## WHAT WAS BUILT: mxfs_dir_merge_peer_blocks(dp) — Phase1 (ILOCK_SHARED) snapshots peer's durable dirents by plain-reading every dir DATA block from the LUN; Phase2 re-adds each missing dirent via its OWN transaction (xfs_trans_alloc tr_create + xfs_ilock(dp,ILOCK_EXCL) + ijoin + xfs_dir_lookup + xfs_dir_createname). Wired at the create PRE-LOCK hook (xfs_inode.c ~1296, after mxfs_dlm_dir_modify_reload_prelock). Gated by mxfs.dir_merge (default OFF). [[sess17-merge-impl-approach-and-txn-blocker]]

## RESULT: FS SHUTDOWN on test2 — "Corruption of in-memory data (0x8) at mxfs_dlm_ilock_begin+0xbc6 (xfs_mxfs_dlm.c:8128)". P17-MERGE fired 0× (shut down before/without re-adding). The mount HUNG (probe iter1 returned empty counts; ops blocked on the shutdown FS). Nodes stayed ssh-alive (OS fine); only the mxfs mount died.

## ROOT OF THE FAILURE: line 8115-8129 — mxfs_dlm_ilock_begin force-shuts-down (SHUTDOWN_CORRUPT_INCORE) when the per-inode DLM lock ACQUIRE returns rc!=0. My merge takes ILOCK_EXCL on dp in a FRESH transaction at PRE-LOCK (before the create acquires the dir lock), PER missing entry — i.e. dozens of independent dir-EX DLM acquire/release cycles per create, under concurrent 2-node load. One of those DLM acquires fails (timeout / unexpected state) → force-shutdown. The approach is fundamentally too heavy AND mis-uses the DLM (churns the dir-EX grant instead of doing the merge once inside the tenure the create already holds).

## LESSONS FOR THE NEXT MERGE ATTEMPT:
1. DO NOT take ILOCK_EXCL / fresh transactions per-entry at prelock — it churns the per-inode DLM grant → acquire failure → shutdown. 
2. Do the merge ONCE, inside the create's already-established dir-EX tenure, reusing the create's transaction context — but solve the dirty-cancel-on-error problem (the original blocker) differently, e.g.: merge as a BUFFER-LEVEL operation on the in-core dir data blocks under the create's ILOCK_EXCL (add the missing dirents directly into the data block buffer + log them via the create's tp), OR defer the missing-entry re-adds to AFTER the create commits (separate well-reserved trans, but ONE trans for all entries, holding the dir lock once — not one per entry).
3. Even if correct, reading ALL dir blocks on EVERY create violates RULE 0 (perf). Gate strictly: only when i_dlm_dir_gen advanced since last merge AND a block is undestaged.
4. Reuse mxfs_dir_evict_data_blocks' per-block undestaged detection to find WHICH blocks need merging, rather than blindly reading all.

## STATE: dir_merge defaults OFF so the DEFAULT build (492C8EB7) is SAFE (== 6D51CDDF + dormant merge code). Recover cluster via fresh prep (reformat+remount clears the test2 shutdown). `./run.sh 2 tcp`=15/16 baseline stands. Marker NOT written. [[sess17-CONFIRMED-staleflush-clobber-P17]] [[sess17-FIX-PLAN-blocklevel-dirent-merge]]

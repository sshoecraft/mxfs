---
name: sess10-FIX-PLAN-use-dlm-grant-gen-not-lossy-evictring
description: sess10 CONCRETE FIX PLAN: use the RELIABLE TCP DLM grant_gen (not the lossy eviction-ring) as the dir staleness signal. NOTE: mxfs_v5_dlm_inode_held…
metadata:
  type: project
---

## THE concrete, implementable fix for the 2/tcp dir lost-update. For [[sess10-double-grant-mht-grant-before-release-hypothesis]] / [[sess10-tcp-dlm-scaling-heartbeat-gen-lag-root]].

## Established facts (sess10, traced in code):
1. DLM master-table double-grant ALREADY fixed (gen-token, build 404BC55C in-tree; dlm/dlm.c dg_grant_ex / grant_gen / dlm_next_gen, stamped on every grant episode, delivered over the acked TCP protocol = RELIABLE).
2. mxfs_dlm_reload_inode (xfs_mxfs_dlm.c ~4799) is RELIABLE when reached: stales the cached inode-cluster buffer (xfs_buf_stale + clear XBF_DONE ~4997) -> fresh FUA re-read from coherent LUN; only skips if the buffer carries THIS node's uncheckpointed mods (P91-RELOAD-PROTECT); shortform-dir self-skip disabled (sess49). So reload-on-reacquire gets fresh peer data.
3. THE BUG: the dir-EX fast path does NOT reach the reload — it trusts cached i_dlm_mode==EX and serves the RMW. The only staleness signal that would trip a reload is i_dlm_dir_gen, bumped by the LOSSY async DIR_MODIFY eviction-ring (note_dir_modified). Lost on TCP -> no reload -> stale-base RMW -> durable dirent resurrection (proven: per-node gen diverged 4 vs 13).

## *** CRITICAL GAP (sess10): mxfs_v5_dlm_inode_held (dlm/v5_mount.c:1350) RETURNS 1 (no-op) FOR TCP *** — it only queries CAW (ctx->dlm_caw). On TCP (ctx->dlm) it punts "don't assert". So ALL slot-ownership detectors (P106-STALE-EX, P108-REACQUIRE) silently do NOTHING on TCP — that is why P106 never fired in the native run. The XFS layer currently has NO reliable way to query TCP DLM grant state. The fix MUST add a real TCP grant-state query against ctx->dlm (the mxfs_dlm_ctx lock table).

## THE FIX: use the RELIABLE TCP DLM grant_gen as the dir staleness signal instead of the lossy eviction-ring.
1. Add `mxfs_v5_dlm_inode_grant_gen(ctx, ino)` (dlm/v5_mount.c + v5_mount.h): for ctx->dlm (TCP), look up the inode resource in the lock table (under table_rwlock) and return THIS node's current GRANTED grant_gen for it (0 if not held). Mirror mxfs_v5_dlm_inode_held's make_inode_resource. (CAW path can return 0/!supported — CAW already has atomic slot mutual-exclusion and does NOT exhibit this bug.)
2. xfs/xfs_mxfs_dlm.c: add per-inode `i_dlm_cached_grant_gen`; set it when a slow-path acquire completes (~7200-7330, where the grant is published / i_dlm_mode set EX). Plumb grant_gen out of the lock acquire (mxfs_v5_dlm_inode_lock) or query it right after.
3. On the dir-EX fast-path serve (the ~6520 dir-strict gate else-block / ~6809 region): query current grant_gen; if it != i_dlm_cached_grant_gen, the lock CHANGED HANDS since we cached it (a peer was granted) -> force slow-path reacquire + mxfs_dlm_reload_inode BEFORE the RMW. RELIABLE; independent of the lossy eviction-ring.
4. MHT preserved: within one continuous tenure grant_gen does NOT change -> fast path keeps serving (no starvation). Changes only when a peer actually got the lock -> exactly the once-per-tenure reload GPT prescribed.

## WHY this beats prior attempts: di_changecount per-node/collidable (UNSOUND, crash_consistency 3/3 fail); eviction-ring lossy; content-compare-while-holding skips on IN_AIL (D0E92AD0 no help). DLM grant_gen is the AUTHORITATIVE, reliable, already-existing "did the lock change hands" token. = GPT's reload-on-reacquire made reliable + MHT-batched.

## VALIDATE FULL `./run.sh 2 tcp` x3 FOREGROUND ([[feedback-never-background-wait-poll]]). Watch dlm_fairness (no starvation got<50) + no wedge. Baseline 5EC1F0BF (=427DB5AF). First read: dlm/dlm.c lock-table lookup (how process_remote_request finds entries: resource_hash + bucket walk + resource_equal + owner==local + state==GRANTED -> grant_gen).

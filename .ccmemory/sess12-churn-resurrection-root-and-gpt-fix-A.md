---
name: sess12-churn-resurrection-root-and-gpt-fix-A
description: sess12 PROVEN ROOT of 2/tcp shared-dir churn resurrection = cached-EX-on-both (a 2nd missed-demote beyond CONVBLK) + lossy heartbeat; GPT-5.5 verdict…
metadata:
  type: project
---

## Criterion = full `./run.sh 2 tcp` 100%. NOT met. Best build = **F967E0F5** (CONVBLK fix only, built locally; next run.sh prep deploys it). Residual ~2-3 fails/CLEAN-REBOOTED run. Marker NOT written.

## PROVEN ROOT: cached-EX-on-BOTH-nodes + lossy DIR_MODIFY heartbeat (NOT strict serialization)
- DIR_MODIFY heartbeat RECEIVER `mxfs_dlm_evict_inode_cb` (xfs_mxfs_dlm.c:10057) only `dir_gen++; set MXFS_IF_DIR_RELOAD`; comment says "safe even if we are concurrently modifying the same dir". Both nodes hold i_dlm_mode=EX cached + mutate via fast path (no DLM round-trip / no BAST).
- SHORTFORM LOSS: dirents inline in parent dinode. NodeA mutating n_a_* dirties the dinode → when it tries to consume MXFS_IF_DIR_RELOAD to adopt NodeB's removal, reload is BLOCKED by `P91-RELOAD-PROTECT` (xfs_mxfs_dlm.c:5057). NodeA keeps stale base (still has n_b_x) → checkpoint writes [n_b_x, n_a_new] → DURABLE resurrection.
- DETECTOR (always-on): `P58-STALE-BASE-ADD` (xfs/libxfs/xfs_dir2.c:447): dir_gen=49 > loaded_gen=47, reload_flag=1. Fired 126×/run.

## CRUCIAL UNRESOLVED SUB-QUESTION (the real next step): WHY cached-EX-on-both still happens
Reasoning says: master serializes EX (CONVBLK fixed); a peer mutate needs real EX → BASTs us → bast_process sets i_dlm_mode=NL → our next mutate slow-paths+reloads. For BOTH to hold cached EX, there must be a SECOND missed-demote / dropped-BAST path beyond CONVBLK (a peer got EX while our i_dlm_mode stayed EX). CONVBLK (deny->EDEADLK on blocked upgrade) was ONE such path; there is another. NEXT SESSION: instrument BAST delivery — count master BASTs SENT (P-DIRBAST @4569) vs node bast_notify honored (stats mxfs_dlm_stat_bast_immediate/deferred/no_inode) for the shared dir ino; find where a BAST is sent but never demotes i_dlm_mode. Suspects: TCP bast msg dropped in-kernel queue; bast_notify branch (ACQUIRING/pin/MHT/NONE-held) whose honor-point is missed; grant_local_new/rearm_unpublished setting i_dlm_mode=EX without a master grant on the SHARED dir after a reuse.

## GPT-5.5 VERDICT (2 consults) = OPTION A: strict dir-EX tenure
Dir MUTATION must hold a REAL exclusive DLM EX tenure; kill cached-EX-on-both for mutators; heartbeat = reader hint only. On BAST: bast_pending; bounded quantum (min-tenure 5-25ms OR N-ops-after-bast 64-256 OR max-bast-delay 25ms); THEN close admission (block new mutators), drain, VISIBILITY BARRIER (log_force_lsn(tenure max LSN)+ail_push_to_lsn_sync+flush shortform cluster buf+blkdev flush), demote. Fresh acquire reloads clean (no P91 block). Quantum avoids sess9-A starvation (got=7/50).
NOTE on the drain-resurrects trap: if i_dlm_mode is left EX on a stale base, ANY release/drain WRITES the stale base = resurrection. So the fix must PREVENT the stale base (enforce exclusivity / find the missed-demote), not just drain on BAST. A shortform snapshot-3way merge (base@load vs in-core vs disk; "if I changed a name vs base, mine wins, else disk wins") is SOUND for the disjoint-name churn tests and is the fallback if exclusivity can't be cheaply enforced (GPT: OK as narrow disjoint-name optimization w/ strict-tenure fallback).

## EXPERIMENTS THIS SESSION (do not blindly repeat)
- CONVBLK fix (F967E0F5): PROVEN double-grant fix (P-CONVBLK-REMOVE→DENY); fixed nothing alone-decisive but correct; keep. [[sess12-convblk-doublegrant-fix]]
- "no MHT-defer for dirs" (build 00F4C5E1): tested on CLEAN-rebooted cluster → still 2 fails (crash_consistency+tcp_dlm_scaling). Prompt release alone does NOT fix it (the cached-EX-on-both window persists pre-BAST). REVERTED. Earlier "5-fail regression" was cluster contamination.
- CONFIRMED: failures are flaky ~2-3/16 per rebooted run; 3 consecutive clean passes once = CHANCE not fix. ALWAYS clean-reboot (virsh destroy+start both) before trusting a run; validate x3. [[env-cluster-bringup-after-host-reboot]]

## TOUCHPOINTS: ilock_begin dir-strict gate ~6546; mxfs_dlm_mht_defer_bast ~4429; bast_notify ~4474; bast_process(visibility barrier) ~2840; reload post_release ~7314; consumer-refresh ~2044; sf refresh+CLEAN-gate ~6240/6267; reload self-skip ~4944-5028; P91 ~5057.

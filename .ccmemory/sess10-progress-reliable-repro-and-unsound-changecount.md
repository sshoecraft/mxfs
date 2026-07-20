---
name: sess10-progress-reliable-repro-and-unsound-changecount
description: sess10 SUMMARY: FULL-SUITE = reliable repro; root=double-grant+lossy heartbeat; fix=tenure serialization (GPT). 2 refuted attempts. Baseline 5EC1F0BF…
metadata:
  type: project
---

## Criterion = `./run.sh 2 tcp` (full 16-test suite) 100% pass. NOT met. Marker NOT written. Deployed (both nodes, healthy): **5EC1F0BF** = 427DB5AF logic + harmless dirwr-gated P-TDS probe + iversion include. Baseline fails ~1-2/16 per full run among {tcp_dlm_scaling, crash_consistency, dlm_fairness}.

## #1 sess10 WIN — RELIABLE REPRO: the residual is RARE standalone (tcp_dlm_scaling 21/21 PASS via `./run.sh 2 tcp tcp_dlm_scaling`) but reliably surfaces in the FULL suite `./run.sh 2 tcp` (warm cluster from 15 prior tests): 1-2 fails/run. ALWAYS validate with the FULL suite x3, native timing (dirwr=0). Standalone + dirwr=1 both HIDE it (Heisenbug).

## ROOT (proven, native dmesg): dir coherency is EVENTUALLY-consistent via a LOSSY async EVICT-RING-DIRMOD heartbeat (per-node i_dlm_dir_gen), NOT strict DLM serialization. Nodes DOUBLE-GRANT the dir (both cache EX) and reconcile via the lossy heartbeat; a missed peer-removal notification -> i_dlm_dir_gen stays==loaded_gen -> stale-base RMW durably resurrects the peer's removed dirent (durable split-brain). All 3 flaky tests = this one root. Details [[sess10-tcp-dlm-scaling-heartbeat-gen-lag-root]].

## DECISIVE FIX DIRECTION (Gemini x2 + GPT-5.5, converged) — [[sess10-gpt-verdict-serialize-tenure-not-epoch]]:
Serialize the dir-EX TENURE. (1) dir-RMW fast path runs ONLY under a REAL writer tenure (no cached-EX-on-both). (2) UNCONDITIONAL reload-on-reacquire after a peer could have held it (don't trust heartbeat gen / di_changecount / content-compare-while-dirty). (3) MHT batching on BAST so reload is once-per-tenure, not per-op (avoids sess9-A starvation). (4) flush-before-handoff (content durable -> release). A CAW shared epoch is OPTIONAL/diagnostic only, NOT the fix.

## REFUTED THIS SESSION (do NOT repeat):
- di_changecount as shared epoch (build 8219ED09): UNSOUND — per-node i_version counters collide under double-grant; disk_cc<=incore_cc wrongly skipped peer reload -> crash_consistency 3/3 FAIL.
- Unconditional pre-RMW FUA shortform compare-reload in mxfs_dlm_dir_modify_refresh (build D0E92AD0): DID NOT FIX — under continuous local churn the node ALWAYS carries un-checkpointed mods, so mxfs_dir_sf_refresh_if_disk_differs's IN_AIL clean-gate skips every time; never adopts peer's change. Plus extra FUA cost regressed dlm_fairness. PROVES: refresh-WHILE-HOLDING can't work (node never reaches clean state while holding) -> MUST be tenure-level.

## NEXT (implement GPT tenure design, CAREFULLY — dir fast-path is deadlock/starvation-prone, validate FULL suite x3 + watch dlm_fairness got<50 + no wedge):
Key code: dir mutation hooks in xfs_inode.c (mxfs_dlm_dir_modify_refresh pre-RMW @2102; mxfs_dlm_dir_durable_signal publish @9962; note_dir_modified heartbeat @9921). bast_notify branches @~4465 (MHT-defer @mxfs_dlm_mht_defer_bast; honor at ilock_end @7374 / unpin). The "evict-ring heartbeat + cached-EX-on-both" is the scheme to REPLACE with strict serialized tenure + reload-on-reacquire for dir EX modifies.

---
name: sess10-tcp-dlm-scaling-heartbeat-gen-lag-root
description: sess10 ROOT (native-timing proven): tcp_dlm_scaling drain-fail = lossy async EVICT-RING-DIRMOD heartbeat gen lag -> stale-base dir RMW resurrects pee…
metadata:
  type: project
---

## Criterion = full `./run.sh 2 tcp` 100% pass. ONLY residual = `tcp_dlm_scaling` (last test). All 15 other 2/tcp tests pass.

## RELIABLE REPRO (sess10): `tcp_dlm_scaling` fails ~1/2 in the FULL-SUITE context (`./run.sh 2 tcp`) but passes 21/21 STANDALONE (`./run.sh 2 tcp tcp_dlm_scaling`). The 15 prior tests leave the cluster "warm" (cached DLM state) which triggers it. Failure: `RESULT FAIL reason=tds shared dir drained(exp=0 got=1)` on rank1 (test1). The test: each node does 150 rounds of create->rename->remove its OWN entry in ONE shared dir; rank1 asserts dir empty.

## HEISENBUG: `dirwr=1` probe (P-TDS-RMW: log dir-EX serve when dir_gen>loaded_gen + on-disk-slot held check) MASKS it 16/16 AND fires 0 times. The probe perturbs timing AND proves `dir_gen>loaded_gen` is NEVER true at the stale RMW — the node thinks its base is FRESH. Build with probe = C5203771 (KEEP probe, dirwr-gated, zero default cost). Base good build still 427DB5AF.

## ROOT (native-timing dmesg at a real FAIL, build C5203771 dirwr=0):
- Dir inode `ino=17313366` (.tcp_dlm_scaling, shortform fmt=1). Per-node dir gen DIVERGES: test1 (FAILING rank1) last `EVICT-RING-DIRMOD ino=17313366 gen->4`; test2 reached `gen->13`. `EVICT-RING-DIRMOD` = the async heartbeat that bumps THIS node's i_dlm_dir_gen when a peer modifies the dir.
- Mechanism: test2 create+rename+removes n2_rK. test1 reloaded the dir at a point where n2_rK.done existed (heartbeat gen->4), RMW'd its own entry onto that base, and NEVER received the heartbeat for test2's REMOVAL (would be gen 5+). So test1's i_dlm_dir_gen stayed 4 == loaded_gen => "fresh" => stale-base detector (dir_gen>loaded_gen) never fires => test1 durably re-publishes a fork still containing n2_rK.done => peer's removed dirent RESURRECTED. Durable split-brain (proven sess10: survived a node1-EX-op BAST that should force peer reload).
- I.e. dir coherency here is EVENTUALLY-consistent via a LOSSY/LAGGY heartbeat, NOT strongly-consistent via the DLM lock. The 1/30 is when convergence loses the race vs rank1's check.

## REFUTED (sess9, do NOT repeat): (A) force slow-path on i_dlm_stale -> STARVATION got=7/50; (B) drop sf_disk_check IN_AIL clean-gate -> WORSE 27/30 (destage-race reverts own committed removal); (C) di_lsn gate -> no gain. sf_disk_check = mxfs_dir_sf_refresh_if_disk_differs (~xfs_mxfs_dlm.c:6175/consumed ~6827), IN_AIL-gated to dodge destage race but that gate skips exactly when peer-stale.

## FIX CLASS (open): make the dir-EX RMW base strongly consistent vs the lossy heartbeat WITHOUT the destage-race revert (reloading own-uncommitted removal). Candidate: shared on-disk dir epoch (FUA-read) instead of async heartbeat gen; or always-reload shared-dir on EX acquire bounded by MHT batching. See [[sess9-gemini-deferred-bast-demote-design]] [[sess9-three-refuted-fixes-for-cached-ex-residual]].

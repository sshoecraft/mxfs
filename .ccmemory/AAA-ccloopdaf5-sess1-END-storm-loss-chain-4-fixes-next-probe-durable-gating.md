---
name: AAA-ccloopdaf5-sess1-END-storm-loss-chain-4-fixes-next-probe-durable-gating
description: sess1 END (relay): 4 fixes 0.10.67-70 (fence patience+listdrain PROVEN, 2 async-release guards). mkdir_storm still loses 1 dirent by r5. NEXT: xfs_in…
metadata:
  type: project
tags: [ccloop-daf50d34, handoff, mkdir-storm, dirent-loss, 0.10.70]
---

# ccloop daf50d34 sess1 END-OF-SESSION state (relay boundary, 2026-07-12 ~17:05Z)

## Builds this session (all deployed via revalidate_cell preps; current cluster = 0.10.70 A6A1EAF824A699B0E9A7A11, 32 nodes mounted, instr=1 dirwr=1 LIVE)
- 0.10.67=27ACCECF: noino fence progress-based patience (mxfs_noino_drain_fence). 
- 0.10.68=462A3DB0: P-AILMIN dump + mxfs_noino_drain_mxfs_buflists stall repair. **PROVEN**: frozen AIL min = inode-cluster buf 0x500020 (DONE|MXFS_ALLOC_QUEUED|DELWRI_Q) = xfsaild FLUSHING dead-end; posix_multi+mmap+zsl@32 all 32/32 PASS after (run71 g1 11/12, only dlm_scaling failed).
- 0.10.69=321DD8D3: noino release gen-anchor (w->rel_gen via grant_gen at BAST entry → unlock_gen). dlm_scaling@32 PASSED 32/32 once on this build (run73).
- 0.10.70=A6A1EAF8: + P-NOINO-LIVE-SKIP (in-core re-check before noino unlock), + P-NOINO-ACQ-WAIT (acquire slow-path waits ≤2s on inflight noino release, xfs_mxfs_dlm.c ~21060), + P15H-LIVE-SKIP (mode!=NL re-check on strand-reap arm ~13720). run74 dlm_scaling 31/32 (test17 rate<floor — rate is marginal ~45-60 vs floor 50 cluster-wide, LUN-bound ~1800 agg ops/s).

## The mkdir-storm bug hunt (scripts/mkdir_storm.sh <N> <rounds> — repro in 1-5 rounds, ~30s/round, RUNS ON STANDING CLUSTER no prep)
Storm = 32 nodes race `mkdir -p .mkdir_storm && mkdir .mkdir_storm/nodeN` then all verify all N present. THREE shapes seen:
1. storm1@0.10.68 r2: node29+node30 lost; PROVEN double-EX (test30 EX .429 + test16 EX .433, same dir gen=4, identical 13-entry P62-SF2BLK bases) → double sf_to_block. Root: test30's own :17 noino async release executed at :18.43x clearing its fresh EX (bast_notify NO_INODE → ungated mxfs_v5_dlm_inode_unlock, xfs_mxfs_dlm.c:14559-ish).
2. storm2@0.10.69 r2: node17's PARENT diverged (test17 .mkdir_storm ino=79691904 vs 71303296 on 31 nodes) = root-dir(128) dirent lost-update — NOTE ino=128 is EXEMPTED (`!= sb_rootino`) from CONVGATE/P14-MODEXT-RELOAD/adopt_block guards. Guard fired 0×; HELD-MISS still 15,622 (gen anchor degrades: grant_meta buckets are collision-LOSSY → anchor reads 0 → unconditional).
3. storm3@0.10.70 r5: node1 (FIRST/shortform-born entry) lost, ALL nodes agree 31 — parent ino=12585041 converted sf_to_block **FIVE TIMES same i_gen** (16:53:06/23/33/42/50, dir_gen 3→39→71→102→105), each from a DIFFERENT random ~13-entry base = **each new EX holder reloaded a STALE dinode** (platter dinode regressing/lagging; canonical-block0 CONVGATE reads the LOSSY grant_meta so it misses too). HELD-MISS down to 5,031 (fixes helping); ACQ-WAIT fired 16×; LIVE-SKIP 0.

## NEXT PROBE (exactly where I stopped)
The dinode-durability enforcement EXISTS: mxfs_inode_cluster_durable (enforcer: log_force+iflush+blkdev_flush, xfs_mxfs_dlm.c:5097) via __mxfs_dlm_dir_inode_durable (5482, handles LOCAL + grown formats) via per-op wrapper mxfs_dlm_dir_inode_durable (5545, gated mxfs_dirop_durable_needed = CAW-only). Call sites: **xfs_inode.c:2336 (xfs_create — mkdir SHOULD route here via xfs_vn_mkdir→xfs_generic_create), 4368 (remove), 4938/4942 (rename)**, plus release-path __ call at 12742.
OPEN QUESTION: why did 5 handoffs read stale bases despite per-op durability? Check:
(a) xfs_inode.c:2236-2340 — the gating comments around the :2336 call (self_created? child-type? deferred?). Confirm mkdir actually reaches it (P13-SFPARENT-DURABLE-FAIL / P68-DIRINODE-DURABLE-FAIL prints in storm3 logs? grep $SP/storm3/).
(b) If durable RAN: the reader side adopted a stale image anyway → P63-HANDOFF "forcing disk-superset adopt" + P62-RELOAD-FORK-SHRINK = reload adopting REGRESSED dinode (fmt EXTENTS→LOCAL!). Fix = reader monotonicity: refuse adopt when disk dinode is OLDER (fmt regression LOCAL<EXTENTS same i_gen, or smaller entry count on LOCAL) — or make CONVGATE read the SLOT (persistent) not grant_meta (lossy).
(c) mxfs_inode_cluster_durable is BEST-EFFORT (25×2ms; pin bails) — P13-SFPARENT-DURABLE-FAIL count in storm3 tells if it's failing under churn.
Storm forensics: $SP/storm_forensics (storm1), $SP/storm2, $SP/storm3 (SP=/tmp/claude-1000/-src-mxfs/f26bc7b6-bcc5-421f-b4cf-e45f69aa126d/scratchpad — EPHEMERAL, dies with session; re-harvest via mkdir_storm+dmesg if needed).

## Criteria ladder state (criteria.json; matrix_check.py --since <final-build-epoch> is the YES gate)
- Historical: full caw matrix PASS but mixed builds; run66/67/68 = 3× dir_reuse@32 consecutive on 0.10.66.
- On 0.10.68+: 32/caw g1 (run71): 11 PASS + dlm_scaling FAIL→ then PASS on .69 (run73) → 31/32 on .70 (run74, rate-marginal test17).
- STILL UNRUN on final build: g2@32 (dlm_membership fence_during_write fault_netpartition crash_consistency), dir_reuse@32, ALL of 16/8/4/2/1.
- REMAINING BUGS before ladder resumes: (1) mkdir-storm dirent loss (above — MUST fix; dlm_scaling got=0 face + posix count misses are this family), (2) dlm_scaling rate marginality at 32 (floor 50 vs measured 45-60; consider playbook caw_epoch_free_reset stale-slot-inheritance fix = designed never implemented; also my ACQ-WAIT adds ≤2s stalls — check it isn't the new rate drag!).
- Tools this session: scripts/probe_sweep.sh, scripts/revalidate_cell.sh (t:<name> for single test), scripts/mkdir_storm.sh, scripts/matrix_check.py.
- Run lock free; no stale run.sh. Awareness docs pal.md/tests.md updated this session.

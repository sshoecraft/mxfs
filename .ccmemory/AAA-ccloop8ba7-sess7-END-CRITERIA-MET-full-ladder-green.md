---
name: AAA-ccloop8ba7-sess7-END-CRITERIA-MET-full-ladder-green
description: sess7 FINAL: CRITERIA MET — 1/2/4/8/16/32-node caw multipath ladder 100% on 0.10.120 (F2443A0C). Root fix P150 read-preserve; evidence in criteria.js…
metadata:
  type: project
tags: [ccloop-8ba7ae5c, sess7-end, criteria-met, ladder]
---

# CRITERIA MET (sess7, 2026-07-17) — full caw multipath ladder green

## Verdict
Every rung of `1/2/4/8/16/32 node caw dlm multipath`: **0 FAIL, 0 SKIPPED, 0 PENDING** on build **0.10.120 / srcversion F2443A0C**, device /dev/mapper/mpatha (2 active paths), transport CAW, RULE0_CALIBRATE=1 (same semantics as all prior criteria rows).
- 1/caw: 30 PASS (suite + caw + all 8 tooling rows re-run fresh on F2443A0C)
- 2/4/8/16/32/caw: 20 PASS each (suite + caw dlm_lock_correctness)
Evidence: `criteria.json` rows (ISO 2026-07-17T02:00–06:00Z band), `./showstat.sh N caw`, `tests/logs/ladder_rung_{1,2,4,8,16}caw.log`, 32-chunk logs in session scratchpad. dir_reuse walls: 32→3417s, 16→1308s. cc@32 3021/3021.

## What closed it (sess7 fixes, cumulative on sess6's 5 fixes)
1. **P150 READ-PRESERVE (0.10.119)** — THE double-alloc root fix (see AAA-...-ROOT-read-clobber-iflush-P150): cold reads of inode-cluster buffers with attached log items now preserve/restore EX-held slots; validated 4 clean repro iters (pre-fix 1-in-2) + full ladder.
2. **P56 ratelimit revert (0.10.120)** — the 0.10.118 diagnostic un-ratelimiting was itself a perf regression (dlm_scaling@32 floor).
3. **Host: VMs ballooned 4G→2.5G live+config** (survives reboots) + swap reset — killed the multi-minute I/O-stall family (heartbeat purges, barrier collapses).

## Operational notes for future sessions
- fio_perf seqW aggregate swings 0.4–7.5GB/s run-to-run on the shared NVMe; fio_perf_vs_xfs worst(write)% can dip <70% when the LUN is busy — rerun on a quiet LUN passes (observed at 4 and 32 nodes). Never kill run.sh mid-fio.
- `scripts/ladder_rung.sh <N>` runs a full rung serially, uncapped, logs to tests/logs/ladder_rung_<N>caw.log.
- Latent, non-blocking: occasional 'Objects remaining in mxfs_ili' at rmmod after abnormal teardown histories (test14, 3×; zero on clean cycles); the sess34 hold-and-wait design tension (folio/ILOCK across CAW poll) unwinds via 120s timeouts under host pressure — both worth future work but did not affect any ladder row.

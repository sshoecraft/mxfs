---
name: AAA-ccloop7251-sess8-END-ladder-sweep-and-next-program
description: sess8 END: cawd ladder 1-32 green (drc@16 bg-finishing); fio phase-barrier fix; drc economics + budget ledger; next = tcp rig 16/32, cawp ladder, fin…
metadata:
  type: project
tags: [ccloop-72513a13, sess8, END, ladder, matrix]
---

# sess8 END state — matrix position and the exact next moves

## Matrix (criteria.json truth at sess8 end)
- **cawd: 1=30/30, 2=20/20, 4=20/20, 8=20/20, 16=18+dlm_lock_corr PASS (drc 24-round was finishing in bg task blsoemb9e — CHECK ITS RESULT), 32=20/20.**
- caw: 130/130 but OLD build records (0.10.120 era) — needs final-build revalidation.
- tcp: 1=16/29 2=17/20 4=17/20 8=17/20, 16/32 = 0. cawp: ALL 0.
- Build on cluster: **0.11.31 = 2A8C8F2668128F276E4D3AF** (P138/P139 anatomy prints, 4MB UDP rcvbuf, BAST resend 100ms).
- Cluster at sess end: 16-node cawd rig (direct iSCSI), running drc.

## How the rungs were run (repeat this recipe)
- Per-rung: `MXFS_FORCE_PREP=1 RULE0_CALIBRATE=1 ./run.sh N cawd prep_cluster`, then the ladder_rung.sh chunk lists as SEPARATE foreground calls (each <10min): chunk1 `precond_readiness posix_single fsx fio_verify integrity_filetypes fault_enospc`; chunk2 `cache_coherency strong_consistency posix_multi mmap_coherency`; chunk3 `zero_silent_loss dlm_fairness dlm_membership scaling_curve dlm_scaling rsync_paired`; chunk4 `crash_consistency fence_during_write fault_netpartition dlm_lock_correctness`; chunk5 `fio_perf fio_perf_vs_xfs`; then dir_reuse_coherency; soak; N=1 only: tooling chunk `mkfs_timing chk_clean online_resize dkms_install single_node_paired fio_vs_xfs_baseline cluster_ops_timing fault_io_error` (reformats LUN — LAST).
- Tests >10min (drc@16+): single bg Bash call, NO outer timeout (kills poison the cluster: fuser -k /tmp/mxfs_run.lock + re-prep needed after any kill).

## Landed this session (keep)
- tests/suite/fio_perf.sh: coord_barrier between workloads at N>1 (4/cawd 42% false-FAIL root-caused: phase drift cross-contamination; manual aligned = 105% of xfs baseline, perfect AG placement, agcount=50).
- 4MB UDP rcvbuf (pal kern.c udp_open) + P138-WAIT extended fields + P139-COLDCLAIM (dlm_caw.c).
- TIMEOUT_BUDGETS.md drc calibration ledger (120s-flat era walls: 1n=112 PASS, 2n=253, 4n=319, 8n=501; 32n 2-round=156s, ~80s/round steady).

## Open debts (ranked next moves)
1. **tcp ladder**: `scripts/rig.sh tcp 32` (LIO/tcm_loop + VM XML rewire + VM cycle), then 1-8 gap fills + 16/32 rungs (`./run.sh N tcp ...` same chunks). tcp 16/32 NEVER run in this ccloop — expect surprises (31-peer TCP mesh).
2. **cawp ladder**: `scripts/rig.sh pass 32` (SCST per-node targets), 6 rungs.
3. **caw revalidation**: `scripts/rig.sh mpath 32`, rungs on final build.
4. **drc@32 standard 24-round record** owed (bg run ~32min; cell currently 2-round-calibrate PASS).
5. **cc@32 enforcing <60s** retry on healthy host (loadavg<4, swap clean): prep + close_release=0 runtime + warm run. 0.11.28 hit 60s; distribution 56-91 tracks host load. Recoverable FS slack: hop gaps ~3-4s + fragmentation tail (adaptive grace: extend only when tenure_ops>=8 & steady rate — designed, not implemented).
6. **rm-wave 8.75ms/unlink** (drc): per-file PR→EX upgrade + teardown wire ops. Cheap A/B queued: is caw_verify_grant_persisted's post-CAS FUA read redundant (CAW is atomic R+W)? Would shave every acquire cluster-wide.
7. task-2 TTL defaults NOT landed (TTL=1500 only trimmed rm 34→28s; releases trickle mid-rm).

## Env doctrine (sess8-proven)
Host swap debt => swapoff/swapon; loadavg>5 => don't trust single-run A/Bs; preps 59s healthy / 200-240s degraded; killed runs => re-prep. VM balloons (2.5G) survive reboots now. worldserver = permanent 1-core background.

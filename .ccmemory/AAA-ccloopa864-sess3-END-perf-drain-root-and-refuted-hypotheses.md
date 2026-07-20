---
name: AAA-ccloopa864-sess3-END-perf-drain-root-and-refuted-hypotheses
description: sess3 END: dir_reuse@32/caw is a PERFORMANCE wedge — per-release drain avg 21.8ms/max 195ms (P138-BAST), bast_process ENTERS 53167x completes only 11…
metadata:
  type: project
---

# sess3 END (ccloop a864) — dir_reuse@32/caw: PERFORMANCE-drain wedge, orphan theory REFUTED

## CRITERIA: only gap = dir_reuse_coherency@32/caw (criteria.json = FAIL 2026-07-11T04:22:22Z; all other tests/nodecounts PASS; dir_reuse passes 2/4/8/16 caw). Must flip to PASS.

## STATE: cluster clean, /tmp/mxfs_run.lock FREE, no run procs. Tree build = **8DE9D5F3** (v0.10.49): force-clear param `caw_orphan_reclaim` DEFAULT 0 (INERT — the v1/v2 fix is dormant), holder-focused P-ORPH-FORENSIC (logs full-scan only when held_raw>=EX). This build with DEFAULT modargs ≈ baseline forensic behavior → wedges ~r18.

## REFUTED HYPOTHESES (do NOT repeat):
1. **"stuck DEMOTING orphan bit → force-clear"** (my v1/v2 fix, P72-ORPHAN-FORCEREL + mxfs_dlm_caw_force_release_self + i_dlm_p72_strikes/MXFS_P72_ORPHAN_STRIKES=16). REGRESSED: fired on TRANSIENT deferred-release windows (P72-SWALLOW state=DEMOTING mode=NL is MOSTLY the normal ilock_end→xfs_trans_free defer window, work_busy=0 until trans commits — NOT an orphan), livelocked at r4 (57593 swallows vs 7656 baseline). Param defaulted to 0. The scan-based force-clear infra (mxfs_dlm_caw_force_release_self, mxfs_v5_dlm_inode_self_held_scan) is retained but inert.
2. **caw_unlock_backoff=1** (release-CAS-starvation theory: 100-retry exhaustion under peer CAS storm). REFUTED — made it WORSE (stuck r4, retry sleeps 1-15ms add latency to every release). bast_process aborts BEFORE the unlock anyway, so backoff never engages.

## THE REAL ROOT (strong evidence, RULE-4): PERFORMANCE — per-release drain cost × 32-way single-dir contention
- **P138-BAST (holder-side release drain cost) for ino131: avg=21784us (21.8ms), max=195675us (195ms), n=743.** Every EX release of the shared dir runs the Phase-2 drain (log_force SYNC + mxfs_dir_flush_data_blocks + AIL push + blkdev_flush). 21.8ms avg × ~100 releases/round × handoff serialization = tens of s/round → 360s barrier timeout → FAIL. RULE 0: 2x native XFS is the ceiling; this is nowhere near.
- **bast_process ENTRY=53167 vs EXIT=full=1198** (per ino131, across nodes). ~52000 entries neither complete the release NOR hit a tagged exit (P15-REL-ABORT=0, P6G-REL-STALE=47, P6ZC-REL-NOANCHOR=74). MYSTERY: where do the ~52000 go? Either an UN-PRINTED early return between P70-BP ENTRY (xfs_mxfs_dlm.c:~10716) and the drain/release, OR they stall/re-queue. This churn IS the wedge. **NEXT SESSION: instrument the bast_process ENTRY→EXIT gap — add an exit tag to EVERY return path, find the dominant early-exit.**
- **Periodic ~4.6s STALLS**: test26 P-DIRBAST timeline gaps (realns 1783748041969→046597 = 4.6s, repeating). Something has a ~4.6s retry/timeout cycle (ACQUIRE_WAIT retry? MXFS_LOCK_WAIT_TIMEOUT? a lease/heartbeat interval?). Find the 4.6s constant. This periodic stall likely paces the whole wedge.
- The EX bit ROTATES among nodes (not one permanent orphan); each holder cycles state=DEMOTING+mode=EX+scan_mine=1 (holds EX, trying to release, release stalls). Bit frees slowly.

## NEXT-SESSION PLAN (RULE 4):
1. Kill any leftover run; baseline build 8DE9D5F3 default modargs = the repro (~r18 wedge). 
2. Instrument the bast_process ENTRY→(no EXIT) gap: tag every return path uniquely; rerun; find where the ~52000 entries exit. That names the release-non-completion.
3. Find the 4.6s stall constant (grep MXFS_*TIMEOUT*, ACQUIRE_WAIT, lease_ms, ~4600ms) — likely the pacing killer.
4. Attack the DRAIN COST directly (the likely real fix): can the per-release dir drain be made cheaper / batched / skipped-when-clean for the reused dir? Look at mxfs_dir_flush_data_blocks + the Phase-2 pipeline. NOTE Architectural Invariant #1 (no unlock without drain) — but a CLEAN dir (nothing dirty since last drain) needs no re-drain. Check if the drain re-flushes already-durable blocks (wasted 21.8ms).
5. Reconsider MHT/tenure batching: if a node could BATCH more creates per EX tenure (fewer handoffs), the per-release drain amortizes. Prior sessions had mxfs_dlm_dir_tenure_keep_delay / MHT — check if it's engaging at 32.

## Diagnostic assets: tests/drc_orphan_watch.sh (greps nodes' dmesg for P70-BP/P138-BAST/P-ORPH-FORENSIC/etc). Watcher out was scratchpad/orph_bkoff (backoff run). P138-BAST + P70-BP are the key perf probes (both always-on, capped 6000/node). Run: nohup timeout 5400 env MXFS_DEV=/dev/mapper/mpatha ./run.sh 32 caw dir_reuse_coherency.

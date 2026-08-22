---
name: ccloop-c7ee71c6-sess204-modeB-errno-EIO-captured-overlay-dormant-fresh-fs
description: sess204: Mode B errno CAPTURED (mkstemp EIO + DLM lock rc=-35 EDEADLK, no source probe); 20-lap soak clean but OVERLAY=0 ⇒ #17 needs AGED fs; zsl+cc…
metadata:
  type: project
---

# sess204 — Mode B captured, #17 soak lesson, two board timeouts

Build 0.11.472 (sv 9EF804271D01AA283D14131) fleet-verified. No code changes this session.

## #17 D-IUNL-LIVESKEW: soak finding
20 consecutive rsync_paired laps ALL PASS 32/32 (4 sess203 + 16 sess204). Fleet-wide
ZERO firings of PENDGRAFT/POSTSTATE/FOSSILFIX/CERT-STACKED/LIVESKEW **and OVERLAY and
GENSKEW**. OVERLAY=0 is the decisive datum: the store-record-live + stale-platter-image
collision NEVER occurs on the fresh fs prep_cluster made for .472 — the .471 failure
cadence (3 fails/4 laps) was measured on an fs AGED by board chunks. Window-widening
delay knob would NOT help (preconditions, not timing, are missing). Reproduction route
for exercising the cert mechanism: run board chunks (dir_reuse, cache_coherency,
crash_consistency churn) THEN rsync laps, survey probes.
TRAP: grep 'P53' matches rsync temp filenames (.file26.A5nP53 → P165-AFFINE-STALE
false positives). Use 'P53-' or full probe names.

## #18 Mode B — errno CAPTURED (sess202 stderr capture worked)
Board chunk 2 run 20260810T135045Z: rsync_paired FAIL test19 3/6 checks:
- RSYNC-ERR: mkstemp "/mnt/shared/.rsync_paired/node19/d3/.file29.eA4RCi" failed:
  Input/output error (5); rc=23; files=401/400 (leftover temp); content sum mismatch.
- Kernel same window: "DLM inode lock failed: ino=... mode=5 rc=-35" (-EDEADLK):
  burst 13:49:49 on inos 56625781-89 (sequential fresh-create range), 13:51:42 on
  ino=39848700 immediately after P-RELOAD-IDENTICAL + P56-RELOAD-MERGE on same ino.
  P70-BP held_ms≈11500 entries on neighboring inos 5662577x. 58 lock-failed lines.
- NONE of the known EDEADLK probes appear (P109-CAW-EDEADLK dlm_caw.c:8051,
  P-SELF-STALE-EDEADLK dlm_caw.c:6081, P-CONVBLK-DENY dlm.c:3865) — ratelimit or an
  unprobed EDEADLK return path. Print site dlm/v5_mount.c:4756 (mxfs_v5_dlm_inode_lock).
- Artifacts preserved: /tmp/run_rsync_paired_20260810T135045Z/ (file `test19` holds
  RESULT+reason; kernlog_test19).
Next: find the unprobed EDEADLK source; trace EDEADLK→EIO in create path; instrument.

## Board on .472 (chunks 1-2 of 5)
- Chunk 1: 7/8 PASS; zero_silent_loss FAIL 32×NO_TERMINAL_RECORD at 60s (workload
  still running, killed). Standalone re-runs 49s→29s→20s PASS. First-run-after-
  20-lap-marathon slowdown; RULE-0 observation, disposition open.
- Chunk 2: 4/6 PASS; rsync_paired FAIL (above); crash_consistency FAIL
  32×NO_TERMINAL_RECORD at 90s, undiagnosed ("reconverged 32/32" after; the
  /tmp/run_crash_consistency_* copy was NOT created — investigate why).
- Chunks 3-5 not yet run (cmds in sess201 transcript fb1d1f15-...jsonl).

## Ops notes
- ssh: tools/mxfs_sshpass.sh testN "cmd" — NO root@ prefix (auth fails with it).
- run.sh preserves fail logs at /tmp/run_<name>_<RUNID>; printed tmp.* dir is deleted.

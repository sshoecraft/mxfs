---
name: sess20-8tcp-residuals-dir_reuse-348s-and-dlm_scaling-flaky
description: sess20(ccloop) 8/tcp with format-gated mht (build 4E047A49) = 16/17 PASS. TWO residuals, both 8-node PERF: (1) dir_reuse in-suite 348s vs 300s cap (2…
metadata:
  type: project
---

## sess20 (ccloop) — 8/tcp = 16/17 via format-gated mht; 2 residual 8-node PERF blockers

### Build `4E047A49` (inode_mht_ms=300 default, dir_sf_mht_ms=100). Two FULL `./run.sh 8 tcp` runs:
- Run A (TEST_TIMEOUT=300 default): 16/17, dir_reuse FAIL (0/8 = 300s timeout).
- Run B (TEST_TIMEOUT=420 diagnostic): 16/17, dir_reuse PASS 8/8, **dlm_scaling FAIL 7/8** (flaky — passed in Run A).
- In BOTH: tcp_dlm_scaling PASS 8/8 (format-gate works) + ALL coherency tests PASS.

### RESIDUAL 1 — dir_reuse SPEED (in-suite timeout): MEASURED in-suite duration = **348s** (test1 phase markers: r1 create-start @204.4s → r24 rm-done @552.7s). Standalone ~277s. The +71s is CUMULATIVE-STATE overhead (~3s/round extra from 12 prior tests). Needs ~50s+ speedup to fit 300s. Per-round ~10-14s in-suite, dominated by create-barrier-wait (4.5-9s, serialized 8-node dir-EX) + rm (3.6s). mht tuning won't help (slope ~0.12s/ms; lower mht faster but breaks coherency; higher mht slower — mht600=314s). RULE-0: 277-348s for this workload is a massive violation (native ~10-30s); real fix = make it FAST.

### RESIDUAL 2 — dlm_scaling FLAKY 7/8: each node does 2000 ops (touch+stat+rm) in its PRIVATE subdir (.dlm_scaling/node$R, NO cross-node contention), pass = ≤60s WINDOW + rate≥50/s. One node occasionally >60s = ~30ms/op = JOURNAL-COMMIT-LATENCY bound under 8-node load. Likely pre-existing 8-node variance (private subdir → sf_mht irrelevant). Passed in Run A, failed Run B → marginal.

### BOTH residuals = 8-node perf/latency (dir-EX serialization + journal commit latency under load), NOT correctness. The deep fix (dir_reuse correct at LOW mht → fast like tcp_dlm_scaling's pipelined 39s) would solve dir_reuse speed; proven first step = postread leaf-fix ([[sess20-PROVEN-dabuf-hole-is-stale-leaf-fixed-by-postread-leaf-only]]), residual block-0x70/AG-double-free deep.

### STILL TO DO for criteria (1/2/4/8 tcp 100%): re-verify 1/tcp (was 16/16 pre-gate), 2/tcp (was 17/17 pre-gate), 4/tcp (was 16/17 pre-gate; tcp_dlm_scaling now fixed — should improve) on build 4E047A49. Then 8/tcp needs dir_reuse speedup + dlm_scaling reliability. See [[sess20-BREAKTHROUGH-format-gated-mht-shortform-dirs-low-mht]].
</body>
</invoke>

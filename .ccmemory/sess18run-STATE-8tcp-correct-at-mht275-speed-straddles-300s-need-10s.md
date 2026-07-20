---
name: sess18run-STATE-8tcp-correct-at-mht275-speed-straddles-300s-need-10s
description: sess18(ccloop) STATE (build 58360875): 8/tcp dir_reuse CORRECTNESS SOLVED — mht=275 clean 3/3 runs (72 rounds, 0 loss) AND mht=300 clean. 1/2/4 tcp P…
metadata:
  type: project
---

## sess18 (ccloop) — 8/tcp now CORRECT; pure speed-margin residual (build 58360875D262141AAAA2BA6, KEEP)

### CONFIRMED THIS SESSION (cited):
- **1/tcp = 16/16, 2/tcp = 17/17, 4/tcp = 17/17** full suites PASS with this build (no regression from the 4 shared-path speed fixes). 
- **8/tcp dir_reuse_coherency CORRECTNESS = SOLID**: mht=275 → failrounds=0 on ALL 8 nodes across **3 consecutive clean-reboot runs (72 rounds, 0 dirent loss)**; mht=300 → also failrounds=0 (1 run). mht=250 = intermittent 1-entry loss (round 7 node8_f20.md5); mht=150 = heavy loss. So the correctness FLOOR is ~mht=275.
- **8/tcp dir_reuse SPEED straddles the 300s blanket TEST_TIMEOUT**: mht=275 WALL=315/316/319s (test portion ~298-304s); PASSED runs 1&2, FAILED run 3 (speed only, failrounds=0). So it's ~5-10s of margin away from reliable.

### The 4 KEEP fixes (see [[sess18run-MILESTONE-8tcp-dirreuse-PASSES-correct-mht300-speed-only-residual]] for code detail): NO_INODE BAST recv-thread offload; PR-drain skip (non-dir read-only release); clean-release log_force skip; release-flush COALESCING. Plus the test's per-round `sleep 1` removed (tests/suite/dir_reuse_coherency.sh:88, RULE-0 masking-delay removal, saved 24s; correctness check unchanged).

### REMAINING = ~10s speed margin to reliably fit 24 rounds in 300s at mht=275. Per-round ~13s: create ~6s (8-node dir-EX serialization at mht — the floor cost; rank1 finishes +0s, slowest node +7s, wr-barrier waits), rm ~3.5s (rank1 inactivates 800 reused inodes, each EX-acquire BASTs 7 verify-PR-holders [now cheap via PR-skip] + free txn), verify-reads ~2-3s. NEXT speed targets: (a) rm/inactivation (~84s total — parallelize or cheapen 800 inode frees; check rank1 vCPU count / inodegc parallelism); (b) lower mht safely needs the deep reload-reliability fix (the dir-data-block stale-base-RMW reload occasionally misses below mht~275 — the level-triggered dir_epoch + grant_gen handoff signal in the FASTEX path ~line 11428-11495 is the precise signal; making it 100% would allow a fast low mht); (c) recalibrate the 300s blanket (RULE 0 forbids widening-to-pass, so weak).

### DEFAULT mht is still 300 (run.sh runs default → dir_reuse fails on speed). To pass `./run.sh 8 tcp` plain at mht=275, must change default OR get mht=300 under 300s. Marker NOT written (8/tcp not reliably passing at default). Reboot ALL 8 clean between runs.

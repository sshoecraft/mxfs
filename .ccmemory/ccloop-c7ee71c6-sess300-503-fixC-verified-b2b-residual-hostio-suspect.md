---
name: ccloop-c7ee71c6-sess300-503-fixC-verified-b2b-residual-hostio-suspect
description: sess300: D-503 fix C VERIFIED (tkt_lost 1.51→0, p99 21.4→8.7s, clean-run max 3.0s); residual = reproducible back-to-back pace degradation, DLM exoner…
metadata:
  type: project
---

# sess300 — fix C verified on rig; residual isolated to non-DLM accumulation

## Fix C verification (0.11.509 sv 92165B241B04D8E70772D2E, deployed via prep_cluster 74s)
- Full accumulation board green: 23 cells PASS 32/caw (incl. dlm_fairness 20s — no D-501-path regression; ag_strand_repair 85s/240s in line with history).
- Collapse chunk PASS first try: crash_consistency 85s/90s, dir_reuse 112s/120s 58/58.
- Census window-vs-window (same mint: adopt exit, el>800ms, dlm_caw.c:6300; baseline preserved at /tmp/tmp.VYmV5C6QY8/p298_test*.txt):
  .508: n=773 med=1466 p90=8788 p99=21432 max=23790 tkt_lost=1.51/wait chosen>0 37%
  .509: n=874 med=1711 p90=7048 p99=8662 max=9324 tkt_lost=0 (ZERO fleet-wide in window)
- Clean dir_reuse PASS run (02:39): n=463 med=1563 p99=2897 MAX=3033 — drain-bounded, exactly the ruled prediction. Starvation component of D-503 is FIXED AND VERIFIED at mechanism level.

## Residual: chronic marginality is back-to-back accumulation, NOT the DLM
Reproduced 4/4: idle ~3min → PASS (104-112s); immediate rerun → FAIL (6-7 rounds <8 in 100s box, always the pace ckeq, faildist 1x32).
- Rounds climb monotonically in-run 9.4s→16.8s, next run STARTS at 16.5s, idle recovers. All phases slow uniformly (wave/wrbar/lookups/rm; rm 2.1→7.6s worst).
- EX-wait census A/B: med 1563→1906, p99 2897→3075 — waits barely move. DLM EXONERATED.
- hostload non-discriminating (FAIL@14.1, PASS@21.9). worldserver = constant 3-core tax, not the variable.
- test1 /proc/fs/mxfs/stat sampled 5s (tests/drc_stat_sampler.sh): per-round rates constant (~780 ail-push, ~400 log_force, 16MB dirty drained), node load <1.2. No local backlog.
- Deferred reap refuted: 0 P89-REAP-DONE on test1 across all runs.
- LUN: SCST vdisk_fileio /home/steve/disk.img o_direct=1 async=1 on clyde nvme0n1.
- LEAD: post-FAIL harness evidence-harvest writes GBs on clyde (Dirty→4.6GB, w_await→150-460ms) — poisons a following run; first pass→fail still unexplained. Trace saved .ccloop/clyde_io_sess300.txt (NOTE sess300's printed table mislabeled columns; correct iostat -x indices: p[2]=r/s p[9]=wkB/s p[12]=w_await p[19]=f/s p[21]=aqu-sz p[23]=dirty_kb appended).

## Open hypotheses for the residual (RULE 4 next)
(a) clyde nvme sustained-write GC/SLC exhaustion (idle recovers) — infra;
(b) harvest dirty-backlog (chains only);
(c) mxfs log-tail pressure: log_force COUNT constant but LATENCY unmeasured — sample xs_log_force_sleep delta per round.
Then RULE-5 consult. If (a)/(b) prove out, residual is infra-attributable — needs hard proof (different backing store / blockio A-B) before any ledger relabel.

---
name: AAA-ccloop7251-sess9-tcp8-CLEARED-pm-degeneracy-vs-methodology
description: sess9: tcp 1-8 ALL GREEN. sess8 "dirent loss" = 3 stacked artifacts (pm re-run degeneracy, drc grind, fio budget 8x). P65 adopt=0 TCP hole documented…
metadata:
  type: project
tags: [ccloop-72513a13, sess9, tcp, posix_multi, fio, methodology]
---

# sess9: tcp@8 front cleared — what the sess8 "catastrophe" actually was

## Matrix state end-state: tcp 1=29/29, 2=20/20, 4=20/20, 8=20/20 (all on 0.11.31 = 2A8C8F26)

## The sess8 tcp@8 reds decomposed into THREE test-infrastructure artifacts:

1. **posix_multi "hardlink-name gone" FAILs = TEST DEGENERACY, not FS staleness.**
   The test never wiped its dir. On every re-run: op_renamed_N exists (prior
   run) as a hardlink of op_src_N's inode; `ln` re-links op_link_N to the SAME
   inode; GNU `mv link renamed` on two hardlinks of one inode = "same file"
   error rc=1, does NOTHING (empirically verified on the VMs). So op_link_*
   legitimately REMAIN, and the `test ! -e` assertions invert: the "FAIL"
   node saw the TRUTH; the 7 "PASS" nodes were the stale ones. FIX LANDED:
   rank1 `rm -rf $D` + barrier at test start (tests/suite/posix_multi.sh).
   6/6 clean PASSes at 8/tcp after fix (17s/30s).

2. **REAL (but latent) TCP staleness observed once (clean run B 13:33:24Z):**
   after an 8-node ln wave on a 5-min-old dir (ino 4195264, epoch ~60), 7/8
   nodes' negative lookups missed ALL peers' fresh adds; P65-EPOCH-ADOPT
   printed grant_epoch 26 AHEAD of valid_epoch with adopt=0 clean=1 — the
   epoch adopt is CAW-ONLY (xfs_mxfs_dlm.c ~17172 `transport_caw && ea_self_clean`);
   TCP's only adopt trigger is the P63 one-shot bit, documented in-code as
   "lost ~80% of the time". Views converged minutes later. NOT FIXED —
   pre-designed fix if it ever gates the matrix: drop the transport_caw
   qualifier (keep post_release + clean-self guards, mirror CAW v0.6.4).
   Diagnostic test landed: tests/suite/dir_add_visibility.sh (NOT in
   manifest — adding a row would retro-un-green completed boards; run via
   scripts/run_adhoc_suite_test.sh N tcp dir_add_visibility). 4/4 PASS at
   8/tcp (24 rounds × 8 nodes = 192 handoffs/run, aging dir, add-only shape).

3. **fio budget violation hidden as calibrate-PASS: tcp fio_perf walls were
   813-1024s vs 120s budget** — rand_write 2GB aggregate at ~1100 device iops
   = ~930s, iops-bound; the 120s budget was bandwidth-derived. FIX LANDED
   (tests/suite/fio_perf.sh): rand workloads use own volume 128/N MB floor 8m
   (FIO_RAND_SIZE overrides); seq keeps 2048/N. Steady iops is volume-blind.
   Post-fix walls: 81s@2, 45s@4, 61s@8. NOTE: cawd/caw fio cells were
   recorded on the old shape — final one-build sweep re-records everywhere.

## fio_perf_vs_xfs yardstick (methodology, landed):
- scripts/raw_fio_ceiling.sh rewritten: fio_perf-shaped legs (same SIZE
  formula, O_DIRECT QD32, double-pass report-2nd), rand legs 256/N floor 8m,
  MEDIAN of 3 samples (RAWCEIL_SAMPLES). Adaptive stripe spacing 46/N G fits
  the 50G LUN at N=32. Single samples measured 254..1153 MiB/s same-N spread
  (host cache absorption vs writeback throttling regimes) — medians only.
- .raw_fio_ceiling.tcp.json (2026-07-19): 2:946/1702 4:384/1755 8:439/1737
  16:603/1665 32:1455/1391 (seqW_mib/randW_iops).
- PAIR IN TIME: gate mxfs numbers captured the same hour as the ceiling;
  vs@2 failed 68% on morning-mxfs vs afternoon-ceiling, passed 101% paired.
- N=32 seqW ceiling 1455 is HIGH (32 deep QD streams absorb better) — the
  32/tcp vs row may genuinely fail <70%; investigate as RULE 4 if so.

## Also re-recorded green at 8/tcp: fence_during_write 18s/60 (97s was
## rung-cascade), soak 33s/60 (mkdir fail was wedge residue).

## drc rewrite VALIDATED: 2/tcp 105s, 8/tcp 107-109s ×4, heavy shape
## (DRC_TOTAL=800 DRC_TIME_BUDGET_S=300) 306s 100/100 checks. Old-shape
## sess8 catastrophic event not reproducible in 10 runs; stays explained as
## old-test grind + wedge cascade. Dossier remains in sess8 memory.

## Infra: scripts/run_adhoc_suite_test.sh = run any tests/suite/*.sh on the
## prepped cluster with run.sh's env contract WITHOUT touching criteria.json.

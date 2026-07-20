---
name: AAA-ccloop7251-sess4-END-sticky-routing-fairness-open
description: sess4 END @7D47BD41: sticky acquire-side routing fixed fio/orphan wedge (fio 2.8GB/s PASS); OPEN: dlm_fairness ghost-dirents knob=1 AND knob=0 wedge+…
metadata:
  type: project
---

# sess4 END — sticky routing landed; dlm_fairness is the open front

Build `7D47BD41736A988E1062B93` (= 0.11.16 + grant_seq + sticky routing).

## Sticky acquire-side routing (the 2nd orphan class, PROVEN + FIXED)
Per-inode file slots were still claimed under knob=1 via the MODE-0 window
(dead-shell recycle acquires at i_mode==0 → S_ISREG false → legacy claim;
release re-evaluated as REG → routed → slot orphaned FOREVER). Observed:
per-inode EX ino=4203201 gen=2201 held 220s, nudge waiters starved, cascade
to root-dir ino=128 EX with 7 nodes queued (fio_perf + dlm_fairness
NO_TERMINAL_RECORD wedges). FIX: ip->i_dlm_routed_iclus stamped at EVERY
acquire (lock_routed routed/legacy, ilock_try both branches, walker-1 pop);
ALL releases + sweep/fan-out + g2/sc_grant_held route by the STICKY BIT,
never by re-evaluating S_ISREG. mode-0-era live grants converted at first
routed claim (P-ICLUS-CONV: drop per-inode slot; gated !unpublished &&
!self_created so fresh creates don't pay a device CAS). VALIDATED: fio_perf
8/cawd PASS 24s (seqW 2802MiB/s seqR 3331 randW 194k randR 229k iops).

## OPEN: dlm_fairness (tests/suite/dlm_fairness.sh — create→mv→rm churn/node
in shared dir, rank1 warm-ls must count 0)
- knob=1: FAIL 7/8, "df shared dir drained(exp=0 got=1..2)" — rank1 sees 1-2
  ghost names, no wedge (11-14s). Reproducible.
- knob=0 (ICLUSTER fully inert): WORSE — whole-test wedge (NO_TERMINAL ×8)
  then 5/8 mounts LOST: "XFS Corruption: Free inode 0x85 has blocks
  allocated!" + trans_cancel shutdown — lost-ifree / double-alloc family
  (the 0.10.120 headline class) triggered by rename churn.
- Session-4 knob=0 deltas are inert branches EXCEPT the xfs_inactive
  EDEADLK one-shot→3-lap retry (same per-lap semantics) — unlikely but
  unverified. Fairness was NOT in sess1-3's regularly-run gate set; suspect
  a pre-existing 0.11.x regression. NEXT: RULE-4 loop on knob=0 fairness
  (repro: MXFS_FORCE_PREP=1 ./run.sh 8 cawd prep_cluster && ./run.sh 8 cawd
  dlm_fairness — corruption on round 1-2, ~30s). Instrument ifree/iunlink
  path for ino ~133 (0x85). If needed A/B the inactive-guard loop revert.

## 8/cawd cell status @ 7D47BD41 knob=1
PASS: dir_reuse(24r calibrate), cache_coherency, posix_multi,
zero_silent_loss, crash_consistency(churned-repro), mmap_coherency,
precond_readiness, strong_consistency, dlm_membership, fio_perf.
FAIL: dlm_fairness (above). NOT RUN: fio_perf_vs_xfs (SKIPped after fio fail
earlier — rerun), scaling_curve, dlm_scaling, rsync_paired,
fence_during_write.
Perf: drc @6r ≈124s vs 120s budget (create dir-EX rotation + rm barrier are
the levers; P138 dir BAST 56ms).

---
name: AAA-ccloop7251-sess6-part2-iclus-wedge-and-pace-program
description: sess6p2 0.11.19 4D510C13: iclus stale-EX wedge killed (backoff+honest unlock+selfclear); 16-rung green; cc@32 3021/3021 at 111/60s; pace program = di…
metadata:
  type: project
tags: [ccloop-72513a13, sess6, iclus, wedge, pace, fair-handoff, 32-node]
---

# sess6 part 2 — 32-rung: iclus wedge fixes + pace science

## Landed (0.11.19, srcver 4D510C131F894486971400E)
1. dlm_caw.c: unlock wall-clock backoff extended to MXFS_LTYPE_ICLUSTER
   (was INODE-only; 100-retry CAS cap exhausted at 32-node churn -> -EIO).
2. mxfs_iclus_unlock + mxfs_iclus_bast_notify: unlock rc captured; failure
   no longer sets disk_mode=NL (the lie orphaned the disk bit AND gated
   release_check off since it requires disk_mode>NL). P-ICLUS-UNLK-FAIL.
3. mxfs_iclus_lock EDEADLK: self-clear escape when sweep shows nothing
   active (fan_out arms nothing in the diverged all-NL state — recovery was
   structurally dead). P-ICLUS-SELFCLEAR. Verified live urc=0.
4. Probes: P-ICLUS-CLAIM / P-ICLUS-UNLK / P-ICLUS-UNLK-BN gated on
   watch_ino==base (echo 128 > /sys/module/mxfs/parameters/watch_ino).

Wedge signature (pre-fix): all 32 nodes P-WAIT-EXTEND type=6 want=3
blockers=<single-slot-bit hex> for 100s+; holder's own claims fail rc=-35
repeatedly; blockers bitmap names the disklock slot -> map via
"claimed heartbeat slot N" in dmesg.

## Test state
- 16/cawd: ALL rows green except drc (skipped). fairness 25/30s tight.
- 32/cawd: fio/strong/precond green; cc FUNCTIONALLY green 3021/3021 but
  111s vs 60s budget. drc@8 501s vs 120s (calibrate green).
- 8/cawd: full 20-row board green (sess6 part 1).

## Pace science (tools: tests/cc_cv_optime.sh, tests/fairness_optime.sh,
## scripts/caw_slot_sampler.py --ltype N, mxfs-CCph markers in cc test)
- Reads scale fine: 32-way storm p50=7ms.
- The single remaining class = contended dir-EX handoff rotation:
  ~65-90ms/handoff (P138: release 5-12ms with su=slot-unlock-CAS 5-9ms
  under herd contention; MHT floor 40ms; nudge discovery fast), tails
  3.5-5.7s from free-for-all CAS races.
- caw_fair_handoff=1 at 32: p90=46s CATASTROPHE — yield_to ticket rotates
  through STALE waiter bits, 5s YIELD_TIMEOUT each. Root: waiter bits not
  dropped promptly at grant/exit; ticket not validated against liveness.
  Keep 0 until hygiene fixed.
- dir_sf_mht_ms=0 at 32: wedges (per-syscall handoff; sess11 class).

## Program to green (in order)
(a) Fair handoff hygiene: drop own waiter bit in the SAME CAS that wins the
    grant (check: is it already?); clear bit on wait-exit paths; ticket
    liveness (skip dead/absent waiters when picking; shorter stale window).
    Then default fair=1 -> single-winner handoff kills the CAS herd.
(b) Adaptive MHT floor: at first quiescent dwork sample, if bpend and no
    local queued/in-flight op, release immediately (skip floor remainder).
(c) Re-measure cc@32 (need 111->60), then drc (rm 7.2ms/unlink, 3.07s
    inter-round), then fairness@32, then tcp/cawp/caw ladders + matrix.

## Cautions
- Cluster left WEDGED at boundary (mht=0 experiment) — FORCE_PREP first.
- Module param experiments persist until reload; prep reload resets them.
- dmesg persists across reload: always timestamp-gate probe counts.

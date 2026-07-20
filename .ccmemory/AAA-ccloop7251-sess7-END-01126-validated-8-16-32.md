---
name: AAA-ccloop7251-sess7-END-01126-validated-8-16-32
description: sess7 END: 0.11.26 (D1AA15A0) validated 8/16/32 — 8: all-green faster (cc 11s), 16: green (cc 25s), 32: cc 56-80s vs 60 bar; wedge chain dead; next l…
metadata:
  type: project
---

# sess7 END state (build 0.11.26 = D1AA15A08A7F7E2D0A0D080)

## Validated this session
- **8/cawd**: cc 11s, zsl 6s, fairness 12s, crash 18s, strong 2s, posix 7s,
  mmap 2s — ALL PASS, all faster than 0.11.21 (quiet-age gate helps low-N).
  drc 6-round calibrate 123s (~unchanged; separate round-pipeline program).
- **16/cawd**: cc 25s, fairness 24s, crash 28s — PASS.
- **32/cawd**: cc functional 3021/3021 every run at 56/60/61/62/70/80s (bar 60
  ENFORCED = NO_TERMINAL kill); fio 36s/120 (2958MiB/s); 0 wedges/forces/
  >2s-waits since the fixes. close_release=0 was RUNTIME-set for all cc runs.

## What landed (see state.md SESS7 PART-1/2/3 + memory ...mht-quietgate...)
FIX1 clocks-clear-on-release; FIX2 MHT quiet-age gate + grace=40 default;
FIX3 honest iclus rc (decline→skip clock clear via p_iclus_declined — NOT
stranded, that retry-stormed); FIX4 gg TCP-only both P135 arms; FIX5
pi_reconcile gated to entry-orphan (p_held_mode==NL) pipelines.

## Next session start here
1. cc@32 last ~10s: audit yield-ticket install during rv-rename EX rotation
   (caw_slot_sampler.py on rv dir, RENAME window — earlier capture only got
   the verify tail). If yt absent → fix fair-handoff for inode slots at 32.
2. close_release TTL defaults (close_release=0 + pr_idle_release_ms~1500) so
   prep stops needing the runtime knob; re-validate drc with it.
3. drc round-pipeline program (rm 800×7.2ms; inter-round rank1 tails).
4. fairness@32 (never run), then remaining 32 rows, then tcp/cawp/caw ladders,
   then matrix_check --cond all.
Installed d_op = pal/linux/xfs_super.c mxfs_dentry_operations (2360);
xfs/xfs_mxfs_dentry.c is dead code. Epoch fast path covers HELD grants only.

---
name: ccloop-c7ee71c6-sess31-P222-first-AB-mask-works
description: P222 A/B + guards: skip=0 wrote 2 dead-tenure images, skip=1 masked (1 landed, 0 wire); FULL guard sweep green with mask on (cache 26s, dir_reuse 110…
metadata:
  type: project
---

# sess31 — P222 stale-stage mask: A/B + correctness guards (all positive)

0.11.271 (`52A1E86B491778368D415E2`) on all 32; one module load, exact deltas:

| lap | knob | verdict | stale detections | masked | wire-writes of class |
|---|---|---|---|---|---|
| dirent_durability | skip=0 | PASS 64s | 2 (both NL) | 0 | **2** |
| dirent_durability | skip=1 | PASS 66s | 1 | 1 (landed) | **0** |
| dirent_durability | skip=1 | PASS 65s | (cum harvest pending) | — | — |

Guards WITH skip=1 active, all PASS at healthy walls:
- cache_coherency 654/654 26s; dir_reuse_coherency 65/65 110s
- crash_consistency 204/204 **24s** — NOTE: its first attempt FAILed
  NO_TERMINAL_RECORD=32 at 90s/90s; that was an INFRA STALL during a host load
  spike (5-min loadavg 18.7, all-32 empty tails = never reached first barrier,
  and the immediate same-build same-knob re-run passed at 24s). Not normalized:
  recorded here with its evidence; if the shape recurs off-spike, re-attribute.
- dirent_publish_integrity PASS with **unlanded_at_unlock=0** (this counter was
  a stuck-at-1 mystery from sess28-29 — first 0 observed WITH the mask on;
  window=1 so thin, but worth tracking as a possible collateral fix).
- sskip_unlanded=0 throughout (the dangerous arm has not occurred).

Harvest mechanics: P219-TOTAL prints on `cluster_authority_dump` (NOT
release_barrier_dump). Counters cumulative per module load. stale_nl counts
DETECTIONS (pre-skip); sskip_* count MASKS; wire-writes = stale_nl − sskips.
Knob currently 1 on live nodes (runtime only; module default is 0).

## Remaining to disposition
1. Accumulate ≥5 detections/arm (keep alternating dirent_durability laps).
2. tests/cluster_authority_merge.sh divergence check with skip=1.
3. Default-ON decision; then GPT conditions 2/4/7 (PUB_SKIPPED consumer audit,
   EX-side epoch gate for class Z, foreign-replay authority gate) and the
   release-quiescence root fix (inodegc must not relog into a closing tenure).

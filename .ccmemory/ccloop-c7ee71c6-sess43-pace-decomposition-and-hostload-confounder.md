---
name: ccloop-c7ee71c6-sess43-pace-decomposition-and-hostload-confounder
description: sess43: dir_reuse round DECOMPOSED (creates+barrier=68%, 64 dir-EX turns/round); grace lever REFUTED; HOST LOAD proven to modulate pace
metadata:
  type: project
---

# sess43 part 3 — the dir_reuse pace defect, quantified

## ROUND DECOMPOSITION (new capability: tests/drc_phase_census.py)
Aggregates the DRCph kmsg phase markers from ALL 32 nodes (drc_analyze.py only
took 2 logs and coarse phases). 0.11.353, 32/caw, 286 phase samples:

round wall median **9.16s** (min 7.4, max 16.1; cross-node spread ~2s)

  segment                     median   share
  create-start->sync1-done     1.97s   19.9%   wave1 creates + sync
  wave1-done->wave2-done       1.71s   17.2%   wave2 creates + sync
  wave2-done->create-done      0.04s    0.4%
  create-done->wrbar-done      2.51s   25.3%   WRITE-BARRIER WAIT (skew)
  wrbar-done->presync-done     0.72s    7.3%
  presync-done->dc-done        1.03s   10.4%   drop_caches
  dc-real-done->ls-done        1.04s   10.5%   cold ls
  ls-done->lookups-done        0.52s    5.2%
  lookups-done->verify-done    0.03s    0.3%
  verify-done->rm-done         0.34s    3.4%

**Creates + their barrier wait = 6.2s = 68% of the round.**

## COST MODEL (fits the numbers)
NFILES = DRC_TOTAL/T = 128/32 = 4 per node, split into 2 waves ⇒
2 waves x 32 nodes = **64 directory-EX turns per round**, ~50ms per turn
⇒ ~3.2s, matching the measured create phases. Consistent with the prior P138
clean-handoff ~13ms + queueing and the 12.7-54ms wire-unlock (CAW round trip
on the shared LUN). **The target is TURNS-PER-ROUND and PER-TURN COST, not
tenure length.**

## LEVER REFUTED (live A/B, 32/caw, 353)
dir_ex_batch_grace_ms 10 / 60 / 150 ⇒ 7 / 6 / 5 rounds. Longer grace is
monotonically WORSE (waiter pile-up), reconfirming sess39 on a current build.
Holding the tenure longer is NOT the lever. Control at grace=10 afterwards: 6,7.

## HOST LOAD IS A REAL CONFOUNDER — measured, and it invalidates careless A/Bs
Same build, same day:
 - hypervisor load 11-17 (morning board) ⇒ **8-10 rounds**
 - hypervisor load 28-30 (Wow.exe 384% + worldserver 315% + tesseract/python)
   ⇒ **5-7 rounds**, and a FULL RE-PREP at high load still gave 7 then 6
Guest-internal load stayed <1 while steal accumulated (test1 steal=7851 ticks)
— the VMs are starved by the hypervisor, not busy themselves.
⇒ NOT mount-degradation-with-use, NOT the grace parameter. The ~1-round margin
over DRC_MIN_ROUNDS=8 is thin enough that host contention alone crosses it,
which is why historical dir_reuse failures cluster in high-load windows.

**SHIPPED MITIGATION:** run.sh now stamps `hostload=` into EVERY recorded
result, so pace numbers are comparable across runs and A/B arms run under
drifting load are detectable after the fact. Any future pace claim without a
hostload stamp is uninterpretable.

## faildist[] instrumentation paid off immediately
The A/B runs recorded `faildist[1x32]` = all 32 nodes failed exactly 1 check,
which for dir_reuse is the final pace assertion — previously indistinguishable
from a real coherency miss without reading node logs by hand.

## NEXT (for the pace arc)
1. Baseline on a QUIESCED host to get the build's true capability.
2. Attack per-turn cost: the CAW wire-unlock round trip on the shared LUN.
   Note 32/tcp historically reaches 11 rounds vs caw 8-9 — lock traffic over
   the network beats the shared SCSI LUN, which points at the transport as the
   per-turn cost driver.
3. Or reduce turns: let a node complete ALL its files for a wave inside one
   tenure WITHOUT extending the tenure clock for waiters (the failed grace
   experiment extended the clock, which is why it lost).
4. RULE 0 governs: the slowness IS the defect. Never widen the 100s box or
   lower DRC_MIN_ROUNDS.

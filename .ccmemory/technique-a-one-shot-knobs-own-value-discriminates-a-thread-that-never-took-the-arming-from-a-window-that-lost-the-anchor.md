---
name: technique-a-one-shot-knobs-own-value-discriminates-a-thread-that-never-took-the-arming-from-a-window-that-lost-the-anchor
description: TECHNIQUE (s134): two s131 laps died on a park confirmation counting 0; reading the one-shot knob back says whether the thread took it or the dmesg w…
metadata:
  type: feedback
tags: [harness, injection, dmesg, vacuous]
---

# Read a one-shot knob back: it says which way the confirmation failed

`tests/parked_log_waiter_across_closure.sh` confirmed its heartbeat park by
writing `dl_inject_hb_pause_ms`, sleeping 4 s, and counting
`P-HB-INJECT-PAUSE.*pausing` in a dmesg window anchored on the mark the lap
emitted at its START. Both s131 arms ABORTed at `stage=park` with
`PAUSE_SEEN=0` — while the subject itself had been produced correctly (the
filler parked in `xlog_grant_head_wait`, stack captured, 7950 transactions).
Two laps and 404 s of rig time were thrown away with nothing to tell the
candidate causes apart:

1. the knob is taken at the TOP of the heartbeat loop, so the line lands up to
   one cadence (`MXFS_DISKLOCK_HB_INTERVAL_MS` = 2000) plus one 64-slot monitor
   pass after the write returns — and this lap has deliberately saturated the
   very LUN that pass reads;
2. the start-of-lap anchor is by then 100+ s and ~8000 transactions old and can
   have left the kernel ring entirely, which empties the window and counts 0
   for a line that is present;
3. the heartbeat thread is genuinely not running.

## The discriminator is free

A **one-shot** knob is cleared by the thread that consumes it
(`mxfs_dl_inject_hb_pause_ms = 0;` at `dlm/disklock.c:2836`, before the line is
even printed). So reading the knob back settles it outright:

* `KNOB_NOW=0` → the thread took the arming, and any zero count is the
  WINDOW's fault (lost anchor / wrong pattern), not the module's;
* `KNOB_NOW=<what was written>` → the thread never reached the top of its loop,
  which is a finding of its own.

Report it alongside the anchored count, the anchor's own presence
(`dmesg | grep -c <mark>`) and an UNANCHORED tail count. Then the abort names
its cause instead of being a coin toss.

Also: anchor the confirmation on a mark written immediately BEFORE the arming,
not on the lap's opening mark, and poll for the line rather than sleeping — the
poll returns as soon as it lands, so a longer bound costs nothing and is not
patience. Bound it from the module's own numbers (6 cadences = 12 s is a fifth
of `MXFS_DISKLOCK_DEAD_THRESHOLD` × interval = 62 s), never from how long
feels safe.

---
name: trap-a-lap-window-opened-before-the-incarnation-under-test-counts-the-previous-laps-pass
description: TRAP (sess593, D-0960): join_during_takeover's A-side window started at the lap marker, so it counted ~7000 activations and quoted the summary of the…
metadata:
  type: feedback
tags: [trap, harness, D-0960, tauth, measurement]
---

# A lap's kernel-log window must open at the incarnation under test

**What happened (s592e, tests/evidence/20260912T072549Z_jointk_s592e):** the harness wrote one marker per iteration and read everything on A from it. A's takeover pass from the PREVIOUS lap (by=A's old incarnation, 182 s, 15365 pages) was still running while step 1 (the 215 s stat) ran, so:

- "activations at issue=7440" was ~7000 old-pass pages plus ~440 of the pass under test;
- the "A pass summary" the verdict quoted was the old pass's summary line (by=<old inc>), while the pass under test had no summary yet;
- the on-demand count (3163) mixed both passes.

None of those flipped the verdict that time, but each is a number that reads as this lap's and is not.

**Fix (tests/join_during_takeover.sh):** a second marker on A written just before A's lone remount; every A-side count, the in-flight detection and the summary read from it (`DMA`). B's window keeps the iteration marker (B's whole life in the lap is one incarnation).

**General rule:** the window a count is scoped to must open at the boundary of the thing being measured (the incarnation, the pass, the mount), not at the lap start. Related: `trap-a-per-load-counter-read-from-the-per-boot-ring-and-the-mount-line-that-anchors-it`, `trap-a-selection-step-keyed-on-a-cumulative-dmesg-count-picks-the-previous-runs-target`.

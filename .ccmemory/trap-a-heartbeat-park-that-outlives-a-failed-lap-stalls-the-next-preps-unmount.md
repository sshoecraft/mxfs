---
name: trap-a-heartbeat-park-that-outlives-a-failed-lap-stalls-the-next-preps-unmount
description: TRAP (s74d→s74e): dl_inject_hb_pause_ms=480000 left armed by an early-exiting lap stalls the NEXT lap's prep, because an unmount waits on the sleepin…
metadata:
  type: feedback
tags: [rig, harness, disklock, injection, cleanup]
---

# A long heartbeat park must be cleaned up on EVERY exit, not just the happy one

`dl_inject_hb_pause_ms` parks the disklock heartbeat thread in
`mxfs_pal_sleep_ms()` for N ms (one-shot, `dlm/disklock.c:2408`). A lap that
needs the victim silent for its whole duration sets it large —
`tests/fence_lost_response.sh` uses 480000.

If that lap exits EARLY (an ABORT at its non-vacuity gate, a kill, a failed
assertion), the thread stays asleep for the remainder. The knob is cleared by a
module reload, but the reload has to get there first: **an unmount waits for
that thread**, so the next lap's `prep_cluster` stalls behind it and can exceed
its own 300 s bound.

Measured: s74d ABORTed at +136 s with the park armed at 480 s; s74e's prep was
still running at +150 s (previous laps: 45-58 s) and had to be abandoned.

## The fix

Arm a trap as soon as the park is set, and destroy the victim on any exit taken
after that point — the victim is destroyed in the tail anyway, so this only
moves the destruction earlier:

    PARKED=0
    flr_cleanup() { [ "$PARKED" = 1 ] && { $VIRSH destroy "$B"; $VIRSH start "$B"; }; return 0; }
    trap flr_cleanup EXIT
    ...
    PARKED=1        # immediately at the park
    ...
    PARKED=0        # in the tail, before the tail's own destroy

Recovering by hand: `virsh destroy <victim>; virsh start <victim>`. Waiting out
the park is the alternative and costs up to PAUSE_MS.

## The general shape

Any injection that makes a kernel thread sleep for longer than the harness's
own remaining runtime is a landmine for the NEXT run on that fleet. Either
bound it by what the lap actually needs, or clean it up unconditionally on exit.

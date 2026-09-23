---
name: trap-mount-busy-covers-two-different-ebusy-causes-and-the-discriminator-is-whether-the-kernel-began-a-mount
description: TRAP (s85): mount(8) prints "already mounted or mount point busy" for EVERY -EBUSY; a 2s holder and a 123s barrier refusal look identical in that tex…
metadata:
  type: feedback
---

# "mount point busy" is a message, not a cause

`mount(8)` prints `already mounted or mount point busy` for **every** `-EBUSY`
the `mount(2)` syscall returns. On this rig at least two entirely different
things return it, and a harness that classifies on the message cannot tell them
apart:

| cause | shape | what the lap is worth |
|---|---|---|
| something else holds the mountpoint | rc=32 in ~2 s, kernel never saw a mount | VACUOUS — nothing was measured |
| the MXFS admission barrier refusing | rc=32 after the full bound (measured 123 s of a 140 s budget) | **the measurement** |

## How it bit

`tests/fence_kind_matrix.sh` grew a vacuity gate after a genuine 2 s leftover
holder wasted an arm. The gate grepped the mount log for the busy text and
`exit 3`'d — **before** taking the kernel window. The next lap of `bind_fsgen`
spent 123 s inside the barrier, met the forged record, was refused, and was
reported as a lap that did not happen, with its only evidence discarded on the
way out. Re-run with the window taken first, the same arm was `fails=0` with
121 claim refusals and 0 replays.

## The discriminator

Not the message, and not the wall time either (a threshold would be one more
guessed constant). Ask the kernel whether it began a mount at all inside this
lap's own marked window:

```sh
window_into "$OUT/B_window.txt" "$B" 90 "$MARK"      # FIRST, always
KERNEL_SAW_MOUNT=$(cnt "$OUT/B_window.txt" \
    'P304-PREOBSERVE\|P-BARRIER-CLOCK\|P240-QUAR-IMPORT\|Mounting Filesystem')
# busy text AND KERNEL_SAW_MOUNT == 0  =>  vacuous
```

## The general form

Capture evidence before classifying the lap, never after. A gate that decides
"this measured nothing" and exits is exactly the gate that destroys the proof
it was wrong. It costs one kernel-log read to be able to check the decision
afterwards.

## The sibling, same session

The same harness's early-exit path restored the forged sector (an `EXIT` trap)
but not the fleet, because the remount lived at the bottom of the happy path.
The reader stayed unmounted, and the retry aborted on its "the reader is
mounted before the arm" precondition — one early exit cost two laps. An exit
path has to put back everything the lap took, and the fleet is part of that.

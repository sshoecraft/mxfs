---
name: trap-a-fix-outside-the-ab-knob-turns-the-control-arm-into-a-second-treatment-arm
description: TRAP (sess567): a follow-up fix added OUTSIDE the A/B knob made the control arm stop reproducing — the control silently became a second treatment arm.
metadata:
  type: feedback
tags: [trap, vacuity, RULE4, sess567, D-0941, measurement]
---

# Anything that changes the outcome must sit behind the A/B knob

## What happened (sess567, D-0941)

`poison_retire_wait` is a 0644 module param whose whole purpose is to run the
defect and the fix against each other in **one build and one boot** — a re-prep
between arms resets accumulated state and makes the arms incomparable.

The first fix (an escalating retry sleep) was correctly behind it. The
second-cause fix — retire the shell when the drain-wait observes the reference
drop — was added **outside** it, because it lives in a different block.

Result on 0.75.106:

| build | arm | unretired |
|---|---|---|
| 0.75.105 | `retire_wait=0` (control) | tracks `poison_n` 1:1, 8/8 node-laps |
| 0.75.106 | `retire_wait=0` (control) | **0** |

The control stopped reproducing the defect. Nothing about the defect changed —
the *control arm had silently become a second treatment arm*.

## Why this is worse than an ordinary bug

An A/B whose control contains the treatment reports success **no matter what the
treatment does**. It cannot fail. The next session reads "control clean, fix
clean" and closes the record on evidence that measured nothing — and this
project has already been bitten by that exact shape twice on this one defect
(the P134 probe comparing fields that cannot move; the injector manufacturing
`got=` empty-content failures).

## The rule

When a knob exists to separate a defect from its fix, **every** change that
alters the outcome goes behind that knob — including a later, separate fix for a
different cause found by the same investigation. The knob defaults to on, so
gating costs nothing in shipping behaviour and preserves the only thing that can
falsify the fix.

Corollary for reading results: a control arm that goes clean after a code change
is not good news. It is the first thing to distrust. Diff what moved between the
builds before believing any arm.

## The result the accident did produce

Worth keeping: with the escalating wait disabled and only the drain-assisted
retirement active, the injected arm still came back clean. So the drain
observation alone is sufficient; the wait is what makes that observation happen
early.

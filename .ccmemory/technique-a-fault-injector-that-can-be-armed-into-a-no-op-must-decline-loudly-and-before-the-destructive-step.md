---
name: technique-a-fault-injector-that-can-be-armed-into-a-no-op-must-decline-loudly-and-before-the-destructive-step
description: TECHNIQUE (s86): the replay cut refused its own vacuous arming and printed why, so a wasted lap cost 137 s instead of two VM boots and a wrong verdic…
metadata:
  type: feedback
tags: [fault-injection, vacuity, harness-design]
---

# An injector that can be armed into a no-op must say so, before the kill

**The case.** The partial-replay cut takes a prefix count: submit N of the
replay's queued buffers, make them durable, withhold the rest, park. If N is
at least the number queued there is no suffix, and "everything was applied" is
the ordinary success the lap is meant to differ from — the experiment has
silently become its own control.

**What was built, and it paid immediately.** The module counts the queue,
refuses the cut when the prefix would leave no suffix (or no prefix), prints
`P-DBG-REPLAY-CUT-VACUOUS` naming both numbers, and then submits normally so
the filesystem is left consistent. The harness looks for that line **between
capturing the prover's window and destroying the prover's VM**, and reports
VACUOUS with the reason.

First lap: `want=8 queued=1`. Cost 137 s and nothing was destroyed. Without
the guard it would have cost two VM boots, ~20 minutes, and produced a lap
whose recovery result looked like a verdict on a cut that never happened.

**The three properties that make it work:**

1. **The injector, not the harness, decides vacuity** — it is the only thing
   that can see the queue at the moment of the cut. A harness prediction made
   beforehand is a guess about a number the workload determines.
2. **It declines LOUDLY and proceeds safely.** Silently doing nothing, or
   silently cutting at whatever it could, both produce a graded lap. Refusing
   and saying which numbers made it vacuous is what turns a wasted lap into a
   diagnosis — and the message named the fix ("raise the dirty workload or
   lower the prefix"), which was the right fix.
3. **The check sits before the irreversible step.** Discovering vacuity after
   the VM is destroyed costs the whole lap to learn nothing.

**Generalises to:** any injector whose effect depends on runtime quantity — a
partial write cut, a torn record at byte K, a "kill after N of M", a delay
that may be shorter than the thing it delays.

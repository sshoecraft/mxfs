---
name: technique-run-the-ladder-backwards-a-fixed-order-sweep-is-confounded-with-elapsed-time
description: TECHNIQUE (sess483): any parameter ladder run in fixed order on un-reset state measures elapsed time as well as the parameter. Run it forward then ba…
metadata:
  type: project
tags: [sess483, measurement, technique, pace, chain129, chain132]
---

# Run the ladder backwards

Chain 129 swept F (files per node) at fixed P=32 and produced a clean monotone
result — mean ms per create 193, 169, 550, 1558, 2151 for F = 8/16/32/64/128 —
which killed two standing hypotheses and looked decisive.

A GPT review found it is confounded, and the confound is generic enough to
write down.

## The confound

The points ran in one fixed order, 8 → 128, on a filesystem that was **never
re-prepped between them**. So two different claims fit the same numbers:

- cost rises with **F**;
- cost rises with **how long the test has been running** — accumulated dirty
  metadata, log pressure, DLM lock objects, background work, fragmentation.

Nothing in a monotone forward sweep separates them, because the parameter and
the elapsed time increase together by construction.

## The fix, and it is cheap

Run the ladder **forward, then immediately backward on the same un-reset
state**:

- **F drives it** → the F→cost mapping *repeats*: F=128 expensive and F=8 cheap
  in both passes.
- **time drives it** → the mapping *inverts*: the reverse pass is most
  expensive at its first point only because it is late, and F=8 comes out
  expensive at the end.

Cost: one extra pass. Value: the difference between an interpretable ladder and
an uninterpretable one. Landed as pass 2 of
`tests/sess483_chain132_dirtenure.sh`.

## Two more from the same review, both generic

**Closed-loop clients mean the sweep variable is not what you think.** With
closed-loop clients that start together, at most P operations are ever
outstanding regardless of F — raising F raises the *duration* of contention,
not the queue depth. **P, not F, is the queue-depth variable.** Saying "cost
rises with outstanding work" when sweeping F is simply wrong, and I had written
exactly that.

**A censored arm's mean is biased, and biased downward.** The F=128 arm
returned 3611 of 4096 samples because its guard fired. The missing 485 are not
missing at random — they are the slowest still in flight. So 2151 ms/create is
a **lower bound**, never "the mean". Always publish n per point and quote a
censored figure as "at least".

## And the signal I had not used

Index 1's mean rose 1464 → 5189 ms across the ladder. Under a FIFO queue where
all 32 first requests enqueue before any second request, the **first**
operation's latency should be roughly independent of F. That it more than
tripled is direct evidence that later requests from fast nodes **overtake**
older first requests from slow ones — barging or owner re-acquisition, an arm
that was not on my list. When a sweep makes the *first* operation more
expensive, ask what that says about fairness before anything else.

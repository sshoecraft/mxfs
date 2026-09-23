---
name: trap-a-design-consults-hazard-ranking-is-hypotheses-not-findings-measure-before-redesigning
description: TRAP (sess580): a consult ranked a shared-key hazard #1 and urged a redesign; instrumenting it showed 114 hits per wait costing zero, and its top fix…
metadata:
  type: feedback
tags: [consult, methodology, measurement, dlm]
---

## What happened

A design consult reviewed a built, measured fix and returned five ranked hazards, with a clear "rank 1, redesign this" verdict on the data structure's key. Acting on that ranking directly would have been wrong three separate ways.

**The #1-ranked hazard was real but free.** It predicted that keying an acquisition record on (resource, mode) rather than per-acquisition would let two tasks share one record and corrupt each other's age and cleanup. Instrumenting it: 114 collisions in a single 240 s wait, so it is reached constantly — and the measured cost was **zero**. 25 blocking notifications with one waiter, 25 with two. Sharing the record is exactly what makes two waiters cost the holder one notification stream instead of two. The sharing was the mechanism working, not failing.

**Its recommended fix would have reintroduced the defect being fixed.** The advice was "use a unique acquisition identity, not a contention key." But the remote master's lookup is `resource_equal && lk->owner == sender` — it models one wait per (resource, sending *node*) and always has. A per-task name fails the master's identity test on a second task's re-send, dropping it onto the replace-and-requeue path, which is one notification per re-send: the exact behaviour the fix removed. The consult could not know this; it had the fix, not the whole codebase.

**Two hazards it ranked mid-list were not observed at all** (eviction and idle retirement: both counters 0 across every lap), and the thing that actually produced a wrong result in that session — a harness probe deciding locality from silence — was not on its list, because it was never shown the harness.

## The lesson

A consult returns **hypotheses with a plausibility ordering**, not findings. It reasons from the code it was shown and cannot see call-site reality, workload shape, or which branches a real system takes. Its ranking reflects how bad each thing would be IF reached, not how often it is reached or what it costs there.

So: take a consult's list as a **list of things to instrument**, and let the instrument set the priority. One counter per predicted failure mode, each probe carrying its own running `total=` (they are rate-limited, so a line count is not an event count), is cheap — it was one build and three laps here — and it converts an argument into an adjudication.

## What made the adjudication trustworthy

Prove the instrument can fire before trusting its silence. A probe that never fires and a system with nothing to report are the same observation. Here the harness gained a mode that forces the predicted collision (two readers of one inode in one mode) and **asserts the probe fired** in that mode. That assertion is what buys every later quiet lap its meaning.

Then run it as a controlled pair — same build, same target, differing only in the one variable — so the difference is attributable. One reader vs two readers on one inode: 0 collisions vs 114, notifications 25 vs 25.

## Also worth keeping

Where a consult IS very good: naming the worst case precisely enough to be checked cheaply. Its most dangerous claim here was "if BAST collection consumes the notification obligation, your gate skipping the fire loses it forever" — a genuine indefinite-wait bug if true. That was settled in one read: collection copies into a local array and mutates no lock state, takes no references, clears no flags. Disproved in minutes, and it left behind a property worth guarding in the awareness doc.

Ask a consult for hazards. Do not let it set the work order.

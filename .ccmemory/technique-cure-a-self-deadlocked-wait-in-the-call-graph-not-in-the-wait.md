---
name: technique-cure-a-self-deadlocked-wait-in-the-call-graph-not-in-the-wait
description: TECHNIQUE (s107): a wait that deadlocks because its own thread is the producer is fixed by moving the CALLER off that thread; self-satisfying the wai…
metadata:
  type: feedback
---

# A wait that deadlocks on its own thread is a call-graph defect, not a wait defect

## The shape

MXFS's post-reset convergence barrier waits for a heartbeat issued after a
LOGICAL UNIT RESET to land. That single observation carries two facts: the
stranded beat has been resolved by the error handler, and this node's authority
lease is still being renewed.

It self-deadlocked, because peer death is declared from the MONITOR stage of the
heartbeat loop and the whole fence ran inside that dispatch. The barrier was
waiting for a beat only the thread executing it could produce. Measured:
`P278-HB-STALL stage=MONITOR`, 30241 ms of waiting against a 30000 ms lease, the
authority closing at its deadline, the survivor shutting its filesystem down.

## The wrong fix, and why it looked right

0.89.34 made the wait issue the beat itself (`mxfs_disklock_beat_now`). The
justification written into the comment was "the SAME proof — same
single-outstanding compare-and-write under the same mutex — it simply no longer
depends on another thread's schedule."

**That dependency was the proof.** Waiting for the heartbeat SERVICE is how the
barrier established the service was alive and renewing. Beating for yourself
establishes that one compare-and-write completed. A node whose heartbeat thread
was parked could then mint a durable retirement certificate and start a replay
that outlives its lease with nothing renewing it, while peers were entitled to
fence it and replay the same slice. Measured as a clean reversal: the injector
arm that parks the heartbeat THREAD went from REFUSE to CERTIFY, 8 assertions
flipping, one change apart.

## The right fix

Move the CALLER. The monitor stage now hands the death to a worker thread that
exists precisely because this class of work must be off the heartbeat thread
(`v5_death_fence_handoff` / `v5_death_fence_drain`, published with a
full-barrier `atomic_xchg`, single producer / single consumer). The wait goes
back unchanged, with **no fallback to satisfying itself** — a heartbeat that
dies under the wait must fail closed.

## The general rule

When a wait deadlocks because the thread executing it is the one that would
satisfy it, there are two edits available:

1. make the wait satisfy itself — cheap, local, and it silently changes what the
   wait proves;
2. move the caller off the producer's thread — larger, touches the call graph,
   and leaves the predicate intact.

**(1) is almost always wrong on a proof-carrying wait.** Before taking it, state
what the wait establishes and check whether the self-issued event still
establishes it. If the answer is "it establishes that the operation completed"
where the wait's purpose was "the SERVICE is alive", (1) has deleted the
property.

A related tell: a comment justifying a change by what it *removes* ("one fewer
dependency on another thread's schedule") is describing exactly what the
mechanism was for.

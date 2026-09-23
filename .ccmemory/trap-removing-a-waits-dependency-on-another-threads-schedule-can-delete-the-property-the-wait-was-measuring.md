---
name: trap-removing-a-waits-dependency-on-another-threads-schedule-can-delete-the-property-the-wait-was-measuring
description: TRAP (s107): a barrier that waited for the heartbeat thread was changed to issue the beat itself to cure a self-deadlock — and thereby stopped provin…
metadata:
  type: feedback
tags: [fencing, dlm, heartbeat, regression, design]
---

# The shape

A wait had a real self-deadlock: the post-reset authority barrier observed "a
heartbeat landed after the reset", and its production caller turned out to be
the heartbeat thread itself. It waited for a beat only it could issue. The
kernel's own stall detector caught it with the heartbeat task's stack inside
the barrier, the 30 s lease expired at its deadline, and the node shut its
filesystem down.

The fix looked obviously right and was written with a confident comment saying
so: issue the beat inline on the caller's thread — "the same proof with one
fewer dependency, on another thread's schedule."

**That dependency WAS the proof.** Waiting for the heartbeat service is how the
barrier established that the service is alive and renewing. Beating for
yourself establishes only that one write completed from whatever thread
happened to call. A node whose heartbeat thread is parked, wedged or dead then
certifies a retirement and starts a replay that can outlast a single lease
interval with nothing renewing it — while its peers are entitled to fence it
and replay the same slice.

# How it was caught, and how it nearly was not

A four-arm harness that had passed one change earlier failed its "lapsed" arm,
8 assertions at once, all of them reversing (`want=barrier-refused`
`got=certified`). The arm parks the heartbeat THREAD and fires the fence from
a debugfs write — a different thread — so the inline beat walks straight past
the injector.

The first reading offered itself immediately and was comfortable: *the
injector is now too weak, the arm tests a thread-park that production would
never produce.* That reading is the trap. In production the same hole is a
wedged or descheduled heartbeat thread, which is not exotic — it is the exact
condition the lease exists to detect.

A design consult put independently reached the same verdict and sharpened it:
**the worker must not fall back to issuing its own beat; a reset witness
proves task retirement, not local authority.**

# The general lesson

When a wait deadlocks, ask what the wait was MEASURING before you ask how to
stop it blocking. "Remove the dependency on another thread" is a correct
instinct for a lock-ordering bug and a silent disaster for a liveness proof —
they look identical at the call site.

If the answer is "it was measuring that some other service is alive", then the
deadlock is in the CALL GRAPH, not in the wait: something long-running is
being executed on the thread whose liveness is the subject. Move the work off
that thread. Do not teach the proof to accept a substitute.

A corollary worth keeping: the same evidence usually says so out loud. The lap
that showed the stall also showed the monitor pass taking 30487 ms — a
multi-second fence running inline inside a lease-renewal loop. That number was
already naming the call graph as the defect.

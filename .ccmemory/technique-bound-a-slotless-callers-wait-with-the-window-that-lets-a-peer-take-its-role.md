---
name: technique-bound-a-slotless-callers-wait-with-the-window-that-lets-a-peer-take-its-role
description: TECHNIQUE (s112): the slotless-bootstrap-owner barrier hang was cured by swapping the SOURCE of both exits, not by adding a timeout — verified live.
metadata:
  type: feedback
tags: [lu-reset, bootstrap, authority-lease, barrier, verified]
---

# A caller with no lease still has a bound — the window in which it can be replaced

Follow-on to `trap-a-barrier-whose-two-exits-are-both-slot-derived-hangs-forever-for-the-one-caller-that-has-no-slot`, which diagnosed the hang. This is the cure and its verification.

## The shape that worked

The barrier waits for "a coordination write of ours issued after the reset has landed" and "we still hold the authority we would replay under". Both were read from slot-derived state. The fix did NOT add a timeout, and did NOT let the waiting thread satisfy its own wait — both had already been tried and rejected in this function's own history (0.89.34 self-beat, reverted in 0.89.36 because it deleted the property being measured). It swapped the SOURCE of each exit:

- the beat: disklock heartbeat timestamp -> bootstrap RECORD write timestamp
- "authority closed itself": lease past its deadline -> abandon window since our last landed record write, or the term already taken over

The bootstrap record write is a real compare-and-write to the same LUN through the same command path, so it converges the reset on the *identical* argument. That equivalence is what makes the substitution legitimate rather than a weaker test.

## The generalisable move

**Ask what window lets somebody else take this caller's role, and bound the wait with that.** A lease-bounded wait looks unbounded for a caller that holds no lease — but every role that can be taken over has such a window, because the takeover rule itself needs one. Using it keeps the wait bounded by the cluster's own rule instead of a number someone picked, and it fails closed for the same reason the lease version does.

## Stamp the ISSUE time, not the completion time

The record write's timestamp is taken where the write is composed, and that same instant is what the reader compares against. So "was a write issued after instant X, and did it land?" is one comparison with no ambiguity about a write that was already in flight when X happened. Stamping at completion would have admitted a pre-reset write that merely finished late.

## Verified, not argued

Lap s112a, 0.89.41: `P307-LURESET-BARRIER ... held=1 arm=bootstrap-term beat_landed=1 wait_ms=1021` and a second at `wait_ms=1028` — one refresh interval each, beats landing 472 ms and 460 ms after the reset. The same lines carry `deadline_ms=0 incarnation=0`, which is the cause printing itself: the disklock authority object was never armed, so the old build's two exits were both unreachable. The whole-cluster restart then completed, both nodes read every fsync-acknowledged payload, and the filesystem checked clean.

## Two corroborations worth reusing as technique

1. **A pinned module is evidence.** The hung node could not `rmmod` (refcnt=2). Reading `/proc/<pid>/comm` and `/proc/<pid>/stack` — never `pgrep -f` — showed the owner's record-heartbeat thread still beating 988 s after the last log line. That proved the liveness service was alive throughout, so the proposed new exit would have fired, *before* a single line of the fix was written.
2. **`MXFS_AUTH_NOT_ADMITTED` reports authority as HELD.** It does so deliberately, so a mount still establishing itself is not refused. Any caller that never lands a beat is permanently in that state, so any gate of the form "has my authority closed?" answers no forever for it. Check that state whenever a wait on the authority gate does not terminate.

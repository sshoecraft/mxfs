---
name: trap-a-containment-assertion-that-counts-a-narrower-pattern-set-than-its-own-capture-fails-a-containment-that-worked
description: TRAP (s108): fence_crash_cuts captured P131-SELF-FENCE as containment evidence but left it out of the count, so a self-fenced victim read contain=0 a…
metadata:
  type: feedback
---

# The capture and the count must name the same set

`tests/fence_crash_cuts.sh` (silent-victim arm) collected the victim's
containment lines with one grep and counted them with another:

- capture (`B_contain.txt`): `P-HB-INJECT-PAUSE | P277- | P-PR-OWNKEY-GONE |
  P305-RESV-SELF | P-PR-SELFFENCE | Shutting down filesystem |
  P131-SELF-FENCE | P236-SELF-FENCE`
- count (`contain=`): the same list **minus both SELF-FENCE names**

Lap s108a (cut 7, `VICTIM=silent`) therefore read `contain=0` and FAILed
`"B contained itself when its heartbeat resumed"` while `B_contain.txt` held

    XFS (sda): P131-SELF-FENCE [AUTHORITY_LEASE_EXPIRED]: this node's own
    heartbeat has not landed for longer than the authority a landed heartbeat
    buys ...

and every fsync in `B_writer.txt` after it returned `rc=1`.  The containment
was working; it was announced under a name the counter did not list.

The FAIL then hit a cumulative `[ $fails = 0 ] || ABORT` gate several stages
later (`stage=deploy`), so the lap died ~5 minutes before the measurement it
was launched for — and the abort message named a stage that had nothing to do
with the cause.

## What to do

- When a harness captures a family of lines as evidence for a property, the
  predicate that JUDGES the property must read the same family.  A capture
  list that is wider than the count is a lap waiting to fail on a working
  system.
- `wait_for_into` sets its variable to the POLL INDEX on success (`0` = found
  on the first poll) and to the literal string `timeout` on failure.  A bare
  `resumed=0` is a hit, not a miss — reading it as a miss sends the whole
  diagnosis the wrong way.
- A cumulative-fails gate reports the stage it sits in, not the stage that
  failed.  Read the FAIL lines, not the ABORT stage.

Related: `trap-a-refusal-with-three-log-names-fails-a-lap-when-the-assertion-cites-only-one`.

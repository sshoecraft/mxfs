---
name: trap-an-expected-durable-state-that-only-one-victim-arm-can-produce-must-not-be-asserted-unconditionally
description: TRAP (s128): fence_crash_cuts cut 1 wants flags=ACTIVE on the victim slot, but the silent arm's own heartbeat park expires its lease so it stamps WIT…
metadata:
  type: feedback
tags: [harness, fencing, measurement-integrity, disklock]
---

# An arm-specific durable state asserted unconditionally fails the other arm

Measured s128, `VICTIM=silent tests/fence_crash_cuts_sweep.sh s127`, cut 1,
0.89.50 srcversion `5E4ABCCB2449C2ECE563AB3`, 2/tcp:

```
  FAIL B1's own record still stands as its stale ACTIVE heartbeat (no intent yet) got=0 want=1
    slot  1 magic=MXLK flags=WITHDRAWN node=585346730 ... epoch=18121864967681530231 ... key_gen=1
```

`tests/fence_crash_cuts.sh:645` asserts `flags=ACTIVE` on the victim's disklock
slot at cut 1 with no reference to which victim arm is running.

## Why the silent arm cannot satisfy it

The silent arm's own setup parks the victim's heartbeat
(`dl_inject_hb_pause_ms=150000`) so that the prover's 62 s dead window can
elapse while the victim keeps its iSCSI session and its writer.  The victim's
authority lease is 30 s.  So ~30 s into the park the victim closes its own
authority and self-fences — `B_contain.txt` carries exactly
`P131-SELF-FENCE` with reason `AUTHORITY_LEASE_EXPIRED` — and the withdrawal
stamps `WITHDRAWN` into its slot.  The at-the-cut capture (+102 s) already
reads `WITHDRAWN`, before anything else has touched the record, and the
writer's last successful fsync is at 32 s after the park, which is the same
lease closing.

`ACTIVE` is what only the **destroyed** arm can leave: a power-cut node is
killed mid-beat and has no opportunity to stamp a departure.

## The shape of the mistake

The assertion's real subject is "at cut 1 the prover died before the intent
CAS, so nothing wrote a fence attempt into the victim's record".  It expressed
that by naming the one state it had seen on the one arm it had run, and the
name became the test.  The generalisation has to be *no RECOVERY_GUARD and no
descriptor*, with the resting state read per arm — never a single literal.

This is the second instance in two days on the same harness family; the first
was an arm that named one node the survivor and graded the winner against it
(`trap-a-two-node-arm-that-names-one-node-the-survivor-...`).  Both are
attribution errors that look exactly like MXFS defects in the RESULT line.

## Also: never edit a harness while a sweep is executing it

bash reads a script by byte offset as it runs, so editing `fence_crash_cuts.sh`
in place while `fence_crash_cuts_sweep.sh` has an invocation of it live
corrupts that invocation.  A fix found from cut 1's output waits for the sweep
to finish; it does not go in between cuts.

---
name: trap-which-node-masters-a-resource-is-a-hash-so-a-two-node-lap-must-establish-locality
description: TRAP (sess579): master locality is a hash of the resource id, so consecutive 2-node laps silently measured different code paths and their counts read…
metadata:
  type: feedback
tags: [harness, dlm, measurement-integrity, false-positive, two-node]
---

# Which node masters a resource is not a constant, and a harness that assumes it measures the wrong path

Which node masters a DLM resource is a **hash of the resource id**. On a
two-node rig that means a harness which creates a file and uses whatever inode
it gets has a coin-flip, per run, over **which code path it exercises** — the
remote-master request path (over the wire) or the local-master queue path (no
wire at all). These are different functions with different waiter handling.

## It produced two false results in one session, both of which passed

**1. A before/after that was two different mechanisms.** `live_holder_wait.sh`
took whatever inode it created. One lap drew a remotely mastered inode (238
blocking notifications at the holder), the next drew a locally mastered one
(237). Those two numbers sat one above the other and read exactly like "the fix
did nothing" — or, with the arms swapped, like a clean 238 -> 0 win. Both
readings would have been wrong. The lap scored **9/9 PASS** while measuring the
path it was not testing.

**2. A gate that counted the wrong node and passed on a zero.** The blocking
notification is fired by the resource's **MASTER**, not by the holder. For a
remotely mastered target the master is the other node, so counting on the
holder works by accident. For a locally mastered target the master is the
*requester itself* — counting on the holder returns 0, and a budget gate of the
form `fires <= budget` scores **0 as a pass**. A zero there is not a good
result, it is a broken instrument: the wait had a blocking holder, so something
fired.

## What to do instead

- **Establish locality, never assume it.** If the code has a probe that only
  runs on the remote path, arming it and seeing it fire IS the proof of remote
  mastering, and its silence is the proof of local. (In MXFS: the
  `dl_drop_lockreq_ino` drop site sits on the remote-master send path only.)
- **Make the lap declare which path it means to measure** and ABORT if it
  cannot get it, rather than measuring the other one.
- **Derive the node you count on from the locality you established**, not from
  the role name (`H`/`W`) — those track holder and waiter, not master.
- **Gate against zero.** Any count that can only be zero when the instrument is
  pointed at the wrong place needs an explicit "this instrument fired at all"
  assertion, or the budget check launders a broken measurement into a pass.
- Two laps are only a before/after if **every** axis but the change is pinned.
  Same inode number is worth checking, not just same file name.

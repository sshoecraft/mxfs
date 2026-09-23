---
name: trap-healing-a-storage-partition-by-removing-the-firewall-rule-does-not-bring-the-path-back-and-the-absence-reads-as-safety
description: TRAP: iscsid tears a dropped session down at replacement_timeout=120s, so un-blocking the portal after a longer partition restores reachability only.
metadata:
  type: feedback
tags: [rig, iscsi, partition, measurement-integrity, vacuity]
---

# Healing a storage partition is not the same as the path coming back

A partition lap that drops a node's iSCSI portal traffic with iptables and
later removes the rules has restored **reachability**, not the session.
`iscsid` gives up on a dropped session at
`node.session.timeo.replacement_timeout` — **120 s by default** — and tears it
down. Any partition held long enough to be interesting (it has to outlast the
62 s dead window plus the fence, so 180 s) is past that.

## Why it produces a false PASS

The interesting question in a fence-then-reconnect lap is whether the fenced
node's registration comes back and, under an all-registrants reservation,
hands it write access again. A lap that stops at "rules removed, now read the
keys" measures:

- key absent → scored as **safety**, when it is only `iscsid` having given up;
- no write from the fenced incarnation → scored as **containment**, when the
  node simply has no path.

Both readings are vacuous and both look like the result you wanted.

## What to do instead

Drive the reconnect and record which of the two happened:

- count sessions before (`iscsiadm -m session`), issue `iscsiadm -m node
  --login` (a no-op when the session survived), count them after;
- prove the LUN is readable again from that node (a direct-I/O single-sector
  read is enough) **before** any verdict is taken;
- if it is not readable, the lap is VACUOUS, not a pass.

The same shape applies to any "break a path, then heal it" lap: the heal has
to be *verified at the layer whose return is the subject*, never at the layer
you broke.

Written while building `tests/fence_partition_reconnect.sh` (s120, MXFS
0.89.46); the guard is in that harness at its reconnect stage.

---
name: technique-reconcile-two-nodes-module-timestamps-through-proc-uptime-and-check-the-anchor-against-the-same-lines-dmesg-prefix
description: TECHNIQUE (s126): every *_ms field MXFS prints is ktime_get_boottime, so two nodes' numbers are incomparable until each is anchored via /proc/uptime.
metadata:
  type: feedback
---

## The problem

Every `*_ms` value the module prints — `deadline_ms`, `now_ms`, `anchor_ms`,
`issued_ms`, `last_ok_ms` — comes from `mxfs_pal_time_ms()`, which is
`ktime_get_boottime_ns() / 1000000` (`pal/linux/kern.c:2970`). That is
**boot-relative**. Two nodes' numbers are not on the same axis at all, and a
harness that subtracts one node's `deadline_ms` from another node's timestamp
is computing a difference of two unrelated origins. The result looks like
seconds and means nothing.

This bites any cross-node boundary measurement: "did the peer act before this
node's lease expired", "did the survivor fence before the victim stopped
writing", "which of the two detectors fired first".

## The anchor

`/proc/uptime`'s first field is the **same clock** (`ktime_get_boottime`). So
read it beside the wall clock in ONE remote command:

```sh
printf 'ANCHOR up=%s wall=%s\n' "$(cut -d' ' -f1 /proc/uptime)" "$(date +%s.%N)"
```

then `wall_at_boot = wall - up`, and any boottime-ms value on that node becomes
wall seconds as `wall_at_boot + ms/1000`. Both reads are in the same shell, so
they are sub-millisecond apart; the nodes' wall clocks are NTP-synced within a
few ms. The windows these laps compare are seconds, so the precision is ample.

## Check the anchor, never trust it

A margin computed across an unverified clock conversion is not a measurement.
The check is free when the module prints a `now_ms` field, because that same
kernel line ALSO carries a dmesg timestamp prefix:

```
[ 5169.041] mxfs: P290-AUTH-CLOSED node 7 slot 1 ... deadline_ms=... now_ms=...
```

Convert `now_ms` through the anchor and convert the `[ 5169.041]` prefix through
the same anchor. They must land on the same wall instant. If they disagree by
more than a few seconds, ABORT: the node suspended, the clock stepped, or
dmesg timestamps are not what the harness thinks they are (they come from
`local_clock`, not `ktime_get_boottime` — equal on a VM that never suspends,
not equal in general). Reporting a margin anyway is reporting arithmetic, not a
measurement.

Implemented in `tests/authority_handoff_phase.sh` (`anchor_of`, `wall_of`,
`dmesg_wall`, and the `ANCHOR_TOL_S` gate).

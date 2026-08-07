---
name: ccloop-c7ee71c6-sess93-takeover-VERIFIED-double-fault
description: sess93: D-RECOVERY-TAKEOVER-UNREACHABLE CLOSED — real double fault on the rig, test5 took over test1's abandoned recovery at stage=3 and published. 3…
metadata:
  type: reference
tags: [sess93, MEASURED, rig, takeover, D-RECOVERY-TAKEOVER-UNREACHABLE, 0.11.422, double-fault, probe]
---

# sess93 — the abandoned-recovery takeover, exercised by a real double fault

`tests/recov_takeover_doublefault_probe.sh` (new). Build 0.11.422,
srcversion `E2D57B3CB50F847A936ACC8`, 32/caw.

## The run

```
probe: mapped 32 node ids
probe: victim slot=3 node=3629992608          (test32, hard kill)
GUARD at t+62.8s
OWNER node=4143148027 host=test1 stage=2 at t+64.6s
probe: destroyed owner test1                  (hard kill, mid-recovery)

P238-RECOV-TAKEOVER slot=3 node=3629992608 owner=4143148027 stage=3
    — the elected replayer died mid-recovery and we proved it dead
P238-RECOV-TAKEN    slot=3 node=3629992608 stage=3
    — RESUME from this stage, do not re-run earlier ones
P163-RECOVERY-COMPLETE slot=3 node=3629992608
                                              (all three on test5)
UNGATED completes = 0
PROBE PASS
```

`stage=3` is `IMAGES_REPLAYED`: test1 had already replayed the slice and died
before publishing, and test5 resumed from that milestone rather than re-running
it. sess91 measured the pre-fix outcome of this exact scenario:
`P163-RECOVERY-COMPLETE = 0` for the whole window, slot frozen at stage=3.

## The two probe-construction lessons — both cost a run

**1. `virsh destroy` must be in the SAME PROCESS as the detection.** The window
between the lease being claimed and the recovery publishing is ~8 s. Any ssh
round trip in the detect→kill path loses it. Solution: poll the **SCST backing
store on clyde directly** — `/home/steve/disk.img`, `O_DIRECT`, 50 ms period —
and `subprocess.run(['virsh',...,'destroy',host])` from the poller itself.

**Host-side O_DIRECT reads of that file are COHERENT with the live cluster** —
verified before relying on it: a live node's heartbeat sector changes across a
1.5 s host-side reread. Superblock at offset 0, disklock table offset at
`sb+64` (measured `dloff=67117056`), slot record = `dloff + slot*512`. In the
record: `magic(0) flags(4) node_id(8)`, descriptor at 40, so `desc.stage` is at
46 and `desc.owner_node` at 84. `RECOVERY_GUARD` flag = 3, `FENCED` stage = 2.
This is a much better vantage point than a guest for anything timing-critical.

**2. The `claimed heartbeat slot` dmesg line is NOT a reliable identity source.**
The first run aborted with `OWNER node=2678771125 host=None`: the owner was the
slot-0 node (the first mounter / longest-lived), whose claim line had rotated
out of its ring — dmesg retention varies ~60x across nodes of one cluster. Only
31 of 32 mapped, and the one that was missing is the one that won.

Fix, now in the probe: **close the map from the platter.** Every ACTIVE
heartbeat record carries its owner's node id, so the ids actually in use are
knowable without any node's cooperation. If exactly one host and exactly one
on-disk id are left unmapped, the pairing is forced. The probe then ABORTS if
the map is still incomplete, rather than discovering it mid-race.

## Why the sess91 phantom-owner injection does not test this arm

It rewrites `desc.owner_node` to a value no live node holds. A phantom is in
nobody's proved-dead set, so 0.11.422 correctly REFUSES to take over ("owner
status unknown → stay blocked"). Takeover needs an owner **this node has itself
fenced**, which means a real node that really dies. Hence the double fault.

## Session tally

Three criticals closed FIXED AND VERIFIED on 0.11.422:
`D-FENCED-STAGE-WITHOUT-PROVEN-EXCLUSION`,
`D-VICTIM-REPLAY-WITHOUT-PROVEN-EXCLUSION`,
`D-RECOVERY-TAKEOVER-UNREACHABLE`.

Six new defects filed from the sess93 RULE-5 ruling's release-blocking list:
`D-FENCE-BLOCKED-STATE-UNOBSERVABLE` (high),
`D-FENCE-CAPABILITY-UNVALIDATED-AT-MOUNT` (high),
`D-PR-REGISTRATION-NOT-PERSISTENT-APTPL` (high),
`D-FENCED-VICTIM-MAY-REREGISTER` (critical),
`D-FENCE-RESERVATION-HEALTH-UNCHECKED` (high),
`D-MIXED-VERSION-UNGATED-REPLAY` (critical),
`D-FENCE-CRASH-MATRIX-UNTESTED` (high).

Ledger 23 open → 27 open. That is the honest direction: wiring the mechanism
exposed what the mechanism still lacks.

## Board / harness note

`showstat.sh` now excludes `win_src=none` runs from the FLAKY tally (both jq
sites). That signature means the P8 scanners' producer workload
(`dirent_durability`) never ran in that boot, so they scanned ZERO lines — the
FAIL is correct (a board must not report a green it did not earn) but a run
that could not OBSERVE cannot CONVICT, so it is not evidence of an MXFS fault.
Seen when this session split the board into chunks and left the producer in the
other chunk; the same criteria passed 32/32 with `win_src=marker` minutes later
on the same build.

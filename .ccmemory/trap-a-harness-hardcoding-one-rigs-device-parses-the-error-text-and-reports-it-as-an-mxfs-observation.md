---
name: trap-a-harness-hardcoding-one-rigs-device-parses-the-error-text-and-reports-it-as-an-mxfs-observation
description: TRAP (sess41): 21 harnesses hardcode /dev/mapper/mpatha with no override and 67 more default to it or the QNAP by-path — all absent on the 2/tcp ship…
metadata:
  type: feedback
tags: [harness, evidence, rig, device, measurement-integrity]
---

# A harness pointed at another rig's device reports the error text as an observation

## What happened

`tests/resv_health_detect.sh` and `tests/pr_reservation_ownership_probe.sh`
both defaulted the shared LUN to `/dev/mapper/mpatha`. That is the CAW
multipath rig's device; on the 2-node TCP rig it does not exist (`/dev/mapper`
holds only `control` and the root LV — mxfs is on `/dev/sda`).

Every `sg_persist` errored. The probe's parser looked for a reservation stanza,
did not find one in the error text, and printed:

```
RESERVATION: NONE HELD   keys=0 distinct=0   (observer=test2)
```

That is an assertion about MXFS's fencing state, produced from a capture that
observed nothing. It failed two assertions against a cluster whose reservation
was in fact healthy WE-AR with 2 registrants — and the same harness's remount
step used the same absent device, so it **silently left a node unmounted** for
the remainder of the run, which changed the behaviour of everything after it.

## Why the existing lesson does not cover it

The known trap is *never derive a count from a capture you have not proven
non-empty*. This is the neighbouring one: **the capture was not empty.** It was
a perfectly good capture of an error message. Non-empty is not the test.

The discriminator has to be a shape the tool emits **only on success**. For
`sg_persist` that is the `PR generation=` header, which every successful
PERSISTENT RESERVE IN carries. The probe now reports `UNKNOWN` and exits
non-zero when that header is absent, instead of reporting `NONE HELD`.

## Scale, counted in the parent over 734 scripts in tests/ and scripts/

- 101 mention `mpatha`
- **21 hardcode `DEV=/dev/mapper/mpatha` with no env override at all** — they
  cannot be pointed at the ship rig
- 28 use `${MXFS_DEV:-/dev/mapper/mpatha}`
- 39 use `${MXFS_DEV:-/dev/disk/by-path/ip-192...}` (the condition-3 QNAP rig)

So 67 are wrong **by default** on 2/tcp and right only if the caller remembers
`MXFS_DEV`, and 21 cannot be made right at all.

## The convention that already exists

`run.sh` resolves this correctly per condition and has all along:

```
tcp  -> DEV_DEFAULT=/dev/sda
caw  -> DEV_DEFAULT=/dev/mapper/mpatha
MXFS_DEV always overrides
```

The harnesses are diverging from a convention the runner already implements.

## What to do in a harness

Take the device from a node's own live mount — it cannot be wrong about which
LUN MXFS is actually using:

```sh
DEV="${MXFS_DEV:-}"
[ -n "$DEV" ] || DEV=$(ssh_helper "$OBS" "awk '\$3==\"mxfs\" {print \$1; exit}' /proc/mounts")
[ -n "$DEV" ] || { echo "FATAL: no mxfs mount on $OBS and MXFS_DEV unset"; exit 2; }
```

And when the device is taken from a node other than the one being unmounted
mid-harness, take it from the node that stays up.

## The general rule

When a harness reads a device, a path or a host from a default, ask which rig
that default was written on. A default that is right on one of four rig
conditions is wrong three times out of four, and it fails by *reporting*
rather than by erroring.

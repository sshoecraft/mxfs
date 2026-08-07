---
name: ccloop-c7ee71c6-sess91-zero-epoch-reachability-measured
description: sess91 reachability MEASURED for zero-victim_epoch recovery descriptors — the lease arm has never fired (0 of all logs), and lease_timeout_ms does no…
metadata:
  type: reference
tags: [sess91, disklock, lease, reachability, measured, over-claim-corrected, lease_timeout_ms, inc_eq]
---

# sess91 — how reachable is a zero victim_epoch, actually

I first wrote into the ledger that the lease detector makes zero-epoch recovery
descriptors "a first-class production path … every lease-detected node death".
**That was an over-claim and I corrected it after measuring.** Recording both
the correction and the method, because the same trap is easy to re-enter.

## What is true

`dlm/v5_mount.c:1405-1432` really does document two detectors, and the lease one
really does pass `(dead_slot = -1, dead_epoch = 0)` deliberately, "to take the
P237-RECOV-INC-UNOBSERVED arm". That is a genuine, intended code path.

## What the rig says

Fleet-wide over every retained `dmesg` **and** `journalctl -k`:

    'lease expired/died' lines with slot -1  →  0.  Never, on any node.

Because the timings are not close:

| detector | window |
|---|---|
| disklock monitor | `DEAD_THRESHOLD(31) × HB_INTERVAL_MS(2000)` = 62s, + a confirm sweep |
| lease | `MXFS_LEASE_TIMEOUT_DEFAULT_MS` = **600000 ms** (`dlm/lease.c:333`) |

The monitor wins by ~5×, always. So the lease arm fires only if the monitor
cannot witness a death for a full 600s — unreadable HB sector, wedged monitor
thread, or a deployment where the disklock monitor is not the detector.

## Bonus finding — `lease_timeout_ms` does not set the lease timeout

The module parameter (`/sys/module/mxfs/parameters/lease_timeout_ms`, currently
`0`) reaches only `mxfs_disklock_set_dead_timeout_ms()` (`v5_mount.c:2637`,
`:2860`), which converts it to disklock samples
(`timeout_ms / HB_INTERVAL_MS`, floor 2). **Nothing overrides `lease.c:333`.**
An operator tuning death detection through the knob that carries the lease's
name shortens only the disk monitor; the lease stays pinned at 10 minutes.
That also means shortening it makes the monitor win by even more, not less.
Filed as item (0) of `D-RECOV-ZERO-EPOCH-DESCRIPTOR-AUTHORITY-UNPROVEN`.

## So which producer actually matters

The one I measured: **the monitor downgrading a known nonzero cached
incarnation to 0** when the sector reads 0
(`D-MONITOR-INCARNATION-DOWNGRADE-TO-ZERO`). That is the producer the probe
exercises, and it needs only a zero on disk — a torn sector, a legacy writer,
or an injection.

## Method note worth keeping

"A code path exists and is documented as intended" is **not** evidence it
executes. `grep` the whole fleet for the probe that would prove it, and check
the two competing timeouts, before writing a reachability claim into the
ledger. One grep and two constants turned "every node death" into "never
observed; requires the monitor to be blind for 600s".

## Also measured, and it removes a suspect

`mxfs_disklock_clear_recovery_pending` (disklock.c:2589) is **already** guarded
for the unknown case — `inc_valid(victim_epoch) && inc_valid(hade) &&
!inc_eq(...)` — so it clears on node identity alone when either incarnation is
unknown. Both probe arms confirmed it: `P237-COMPLETE-REARMED = 0`,
`P237-PENDING-REARMED = 0`. It is not a wedge site. It does mean the sess86
COMPARE-and-clear silently degrades to a NODE-scoped clear whenever either
incarnation is unknown, which is the hazard that check exists to prevent — kept
in the ledger as a consequence, not as a suspect.

## Probe structure lesson (cost me two runs)

`incarnation_mismatch_probe.sh` originally censused the survivors right after
the detect window. The interesting half is the **second** death round, which has
not started yet at that point — so the census reported a window that stopped
short of the evidence and read as "nothing happened". The census now runs
**after** the self-heal watch. Related: the arm assertion must be scoped to
"no descriptor was published for the REFUSED incarnation `$PEPOCH`", not "no
descriptor at all" — the second round legitimately publishes one, and that is
what reclaims the slot.

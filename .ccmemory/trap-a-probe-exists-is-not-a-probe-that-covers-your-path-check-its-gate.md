---
name: trap-a-probe-exists-is-not-a-probe-that-covers-your-path-check-its-gate
description: TRAP (sess481): P132-CREATE decomposed create cost since sess132 but started its clock under `is_dir` — 349 sessions of file-create work had no probe.
metadata:
  type: feedback
tags: [trap, instrumentation, probes, sess481, rule4]
---

# TRAP (sess481): "the probe exists" is not "the probe covers your path"

`xfs/xfs_inode.c` `xfs_create()` has carried `P132-CREATE`, a five-phase cost
decomposition of one create, since sess132. A survey looking for "is the create
path instrumented?" answers **yes** and moves on.

It started its clock under:

```c
if (mp->m_mxfs_dlm && is_dir)
        p132_t0 = ktime_get_ns();
```

`is_dir`. Every workload that sets this filesystem's create ceiling — the
32-node `crash_consistency` row, the create-scale curve, the shared-directory
pace record — creates **files**. So the one probe that could attribute a
create's cost had never run on the path that mattered, for ~350 sessions, while
that cost was the open question on a top-priority record.

The comment even said so, in a way that reads as a reason rather than a
limitation: *"Always-on for DIR creates on multi-node mounts only (mkdir is rare
outside the storm)"*. That was true of the workload sess132 was looking at, and
silently false of every workload since.

## The rule

When a survey reports that a code path is instrumented, **read the probe's arming
condition before believing the coverage claim.** Three things to check, in order:

1. **The gate on the clock**, not just the gate on the print. A probe can be
   compiled in, enabled, and above threshold, and still never start its timer.
2. **The threshold.** `P138-ACQ` fires only above 5 ms; a path that is uniformly
   3 ms shows as silent, which reads identically to "fast" and to "not measured".
3. **The print cap.** Several probes here stop after N events per boot
   (`P291-EXWIN` at 20000, `P138-ACQ` at 4000). A long run's tail can be missing
   for no reason but the counter.

A related shape from the same session: an *absent* measurement and a *zero*
measurement look the same in a report. `tools/p132_attribute.py` therefore
refuses to print a table when no input carried the probe, rather than printing
zeros — the same reason `tests/suite/lib.sh` now separates `notrun=` from
`failed=`.

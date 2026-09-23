---
name: trap-a-repair-sitting-at-the-measurement-point-destroys-the-evidence-it-would-have-produced
description: TRAP (sess577, D-0496): the defect record named two masks; a THIRD repair sat at exactly the acquire point where the producer was visible, and it had…
metadata:
  type: feedback
---

## What happened

D-0496 (directory LEAF hash index diverges from the DATA blocks after death+replay)
had resisted rooting for days. Its record names two masks that hide the symptom:

- `mxfs_dir2_datascan_lookup` — rescans every data block on ENOENT (lookup face)
- `mxfs_dir2_leafless_removename` — expunges a dirent the leaf does not reference (remove face)

Both are gated by the `dir_datascan_heal` knob, and every experiment on this defect
turned that knob off to make a lap non-vacuous.

**There is a third repair, on a different knob, and nobody counted it.**
`mxfs_dir_rebuild_leaf_from_data` (`xfs/libxfs/xfs_dir2_leaf.c`) is fired from
`xfs_dir_createname` gated on `MXFS_IF_DIR_LEAF_STALE`, which is armed **once per
cross-node tenure** and consumed BEFORE that tenure's first mutation. It rebuilds
the leaf from the data blocks and reports only the REBUILT count
(`P26-REBUILD-OK nent`). Knob `dir_leaf_rebuild`, **default 1**.

That location is not incidental. It is exactly the point where an incoherent
ACQUISITION is observable — the leaf sitting there is the one the node received
from the handoff, before it has modified anything. So the one place the producer
was directly measurable was also the place a default-on repair overwrote the
evidence and reported nothing about what it had repaired.

## The general lesson

When hunting a producer that "never reproduces", enumerate **every** repair path
that can touch the object, not the ones the defect record happens to name. A
record lists the masks that were found; it does not list the ones that were never
noticed. Ask specifically: *is there a repair running at the exact point my
measurement would have to be taken?* If so, it is not merely hiding the symptom —
it is consuming the measurement.

Related and already recorded: a guard written for one direction leaves the
symmetric direction open; a silent instrument and a clean system are the same
observation.

## The fix shape that worked

Do not remove the repair to see the evidence — that changes behaviour and risks
the thing the repair exists to prevent. Instead make the repair **report what it
repaired**: snapshot the pre-repair state, diff it against the post-repair state,
emit both outcomes (divergent AND clean). Zero extra I/O when the repair already
has both sides in hand, no behaviour change, and the counts give free coverage
accounting — if the census count does not equal the repair count, the instrument
is blind and says so.

Landed as `P496-ACQ-DIVERGE` / `P496-ACQ-CLEAN` in 0.79.0.

## Coverage caveat that came with it

The first run (2 nodes / TCP, shared-dir reuse workload) produced 36 censuses
matching 36 repairs exactly, zero divergence — but 81 further rebuilds declined on
directory format, so the window covers single-leaf directories only, and the diff
ran against in-core data rather than the platter. A clean census under those limits
is a bounded negative, not a disproof.

---
name: technique-audit-by-primitive-every-caller-of-the-thing-that-must-not-be-called-unprepared
description: TECHNIQUE (sess482): audit BY PRIMITIVE, not by scenario — enumerate every caller of a function that must not be called unprepared. Found a critical…
metadata:
  type: project
tags: [technique, audit, invariant, unmount, drain, d408, rule6]
---

# Audit BY PRIMITIVE — every caller of the thing that must not be called unprepared

## The move

Sessions here fix defects **by scenario** ("the dirty-departure case", "the
BAST release path"). That leaves a predictable hole: when several callers reach
one primitive, hardening lands on the caller that was being debugged and the
others are never brought along. **Nobody notices, because the fixed path is the
one everyone looks at.**

So: pick a primitive with a precondition, enumerate **every** caller, and diff
what each does before calling it.

## The instance (sess482)

`mxfs_v5_dlm_ag_unlock` (`dlm/v5_mount.c` ~15071) is a **pure** release
primitive — TCP unlock or CAW slot CAS behind a release gate, no draining, no
flushing. Architectural Invariant #1 says no on-disk DLM unlock without a
completed drain pipeline, so every caller must prepare the platter itself.

Two callers:

- cooperative release (`~49457` → unlock `~49710`): **nine** steps first.
- unmount `mxfs_dlm_ag_force_release_all` (`~49924` → unlock `~49970`): **one**.

The closed `D-AGI-UNLINKED-CROSSNODE-RECOVERY-SHUTDOWN` records the sess385
fix as *"drain_alloc_buflist + drain_inode_buffers now run BEFORE the first
drain_meta_buffers, with a blkdev flush between"*. That went into the
cooperative path. The unmount path still runs one of nine. Filed as
`D-UNMOUNT-AG-RELEASE-SKIPS-DRAIN-PIPELINE-INVARIANT1-482` (critical).

## Why it was worth doing

It produced a candidate mechanism for `D-AGIFC-...-408` — **#1 critical, whose
mechanism had been UNKNOWN for twelve days** and whose four candidate arms were
all about *replay*. Its symptom is AGI freecount vs inobt/finobt divergence
*after a clean fleet unmount*, plus an orphan still chained in an AGI unlinked
bucket. The cooperative path's own sess43 comment predicts exactly that from
skipping the meta drain. Nobody had looked at what unmount itself does.

## The second lesson: an oracle's silence needs a denominator

A platter-reading audit already ran one line above the unmount unlock,
default-on, and had **never** reported a mismatch in 938 evidence directories.
That looked like exoneration. It had **four silent early exits** (off/no DLM,
single-node, `xfs_is_shutdown`, read failure, and multi-level btree — it bails
unless `agi_level == 1 && agi_free_level == 1`), none of them counted.

**A zero from an instrument that may not have run is not evidence of
anything** — the same failure as the vacuous P165 probe, one level up. 0.67.0
counts every exit by reason and prints `ran` as the denominator. Also uncounted:
both the audit and the unlock sit inside `if (release_now)`, so AGs handed off
cooperatively before unmount are never examined here at all.

**Whenever you are about to read a clean sweep as evidence, ask what fraction
of the calls the instrument actually completed. If nothing counts that, the
sweep is not evidence yet.**

## And: do not "fix" it before measuring

The obvious patch — copy the nine-step pipeline into the unmount path — would
add up to three device flushes per AG to every unmount and could turn a
correctness gap into a RULE 0 failure on the mass-unmount rows. Instrument
first; the right size of the problem is not known yet.

## Where to point this next

Any primitive with a stated precondition and more than one caller. Start where
a closed record says "now runs before" or "reordered" — that phrasing means one
path was fixed, and it rarely says whether the siblings were.

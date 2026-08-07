---
name: ccloop-c7ee71c6-sess25-unmount-leak-attributed-and-linked
description: D-UNMOUNT-BUSY-INODES: leaked ref ATTRIBUTED (xfs_lookup, refcount-level table) + causally linked to the demoter clobber 3/3 vs 0/4. Cancel-leak refu…
metadata:
  type: project
tags: [unmount, inode-leak, refcount, P203, rule4, ab-test]
---

# sess25: D-UNMOUNT-BUSY-INODES — reference attributed, cause linked

## The instrument that finally worked: GRAB-BY-REFCOUNT-LEVEL

sess23's `P202-REFEV` ring "never produced a capture" because it is a fixed
10-entry **history window**, and by unmount it has wrapped many times. A leak
is an OLD grab with no matching release — a history window structurally cannot
hold it.

A push/pop **stack** was tried and is WRONG — measured: `depth=12 over=19
under=0` on its first capture. Grabs are tracked but plain VFS `iput()` from
dentry eviction is not, so pushes outnumber pops and it only grows. **Do not
reinstate it.**

What works: record the grab that took `i_count` to N in **slot N**. With
`icount=1` at unmount, slot 1 IS the outstanding reference. Self-correcting —
it never observes a release, so untracked `iput()`s cannot desynchronise it.

    P203-GRABLEVELS ino=29360571 icount=1 over=0
      P203-LEVEL[1] xfs_lookup+0x16c          <- THE SURVIVOR
      P203-LEVEL[2] mxfs_dlm_bast_notify+0x6f
      P203-LEVEL[3] site=file1:line26265
      P203-LEVEL[4] site=file1:line26690

Levels 2–4 are the DLM machinery's own grabs, all released. The survivor is an
ordinary namespace lookup, on an inode with `dentries=0 hashed=1 lru_linked=1`.

## Refuted by measurement — do not re-chase

**Cancelled-arm leak.** `mxfs_dlm_evict` cancels both BAST arms, each armed
holding an igrab whose only drop is inside the work function — so a cancel of
QUEUED work would leak exactly one ref, and the signature (icount=1,
dwork_pending=0, bwork_pending=0, bast_pending=0, PR/CACHED) fits perfectly.
Probe `P204-CANCEL-ARMED-REF` fired **zero** times across the full reproducer.
The pre-existing comment ("the dwork holds an iget ref that keeps the inode out
of reclaim, so it has already run by the time we reach evict") is correct.
Repair knob `mxfs.cancel_ref_release` exists and ships OFF — it repairs a case
that does not occur.

Also corrected: a prior session read `bast_pending=0` as evidence AGAINST the
dwork. That inference is backwards — `mxfs_dlm_evict` clears that flag
immediately after the cancel.

## Causal link to the demoter clobber

Paired A/B on ONE build (0.11.213) via the negative control
`mxfs.demoter_legacy_clobber` (restores the pre-sess25 unqualified
`i_dlm_demoter` claim):

| arm | leaked |
|---|---|
| `demoter_legacy_clobber=1` (bug re-armed) | **3 of 3 cycles** |
| `demoter_legacy_clobber=0` (fixed) | **0 of 4 cycles** |

All three captures identical: one DIRECTORY, icount=1, dentries=0,
dlm_mode=3 PR, dlm_state=1 CACHED, `iget_caller=xfs_lookup+0x16c`.

Driver: `tests/unmount_leak_repro.sh [N] [cycles]`, env `MXFS_LEGACY_CLOBBER=1`
selects the broken arm.

## Kept OPEN deliberately

1. The **mechanical chain** from "claim clobbered" → "level-1 lookup reference
   retained" is not traced; what exists is a controlled A/B. Cheap missing
   measurement: on a leaking legacy-clobber cycle, check the leaking node for a
   D-state kworker wedged in the demote-wait.
2. The **historical signature differs**: sess22 recorded `still_referenced=775`
   REGULAR FILES with NO DLM state. Every sess25 capture is ONE DIRECTORY with
   PR/CACHED. Eliminating the reproducer's shape does not dispose of the
   originally reported one. A clean reproducer is not a disposition.

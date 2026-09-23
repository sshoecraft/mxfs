---
name: trap-rebuilding-the-module-while-a-rig-lap-runs-splits-the-sweep-across-two-builds
description: TRAP (s123): every arm of a sweep re-preps, so a `make modules` during a sweep deploys the NEW mxfs.ko to later arms and the sweep spans two srcversi…
metadata:
  type: feedback
tags: [measurement-integrity, rig, build, delegation]
---

# A rebuild during a running sweep silently splits it across two builds

Rig sweeps in this tree are a loop over arms or cuts, and **each arm runs its
own `MXFS_FORCE_PREP=1 ./run.sh 2 tcp prep_cluster`**, which copies whatever
`mxfs.ko` is in the tree at that moment onto both nodes. So `make modules` in
the middle of a sweep does not "queue up for later" — it reaches the very next
arm.

Measured: sweep `s123a` launched on `0EA704DBF87AFF66D6CA9DE`; a rebuild landed
between arms; the storage arm's prep printed `0EA704DBF87AFF66D6CA9DE` and the
network arm's printed `5E4ABCCB2449C2ECE563AB3`. Each arm's own
`ck "prep deployed the tree build"` PASSed, because each harness reads
`modinfo mxfs.ko` at its own start — so **nothing in the harness catches this**.
The only place it shows is the two prep lines, side by side, in two different
consoles.

Two consequences, and the second is the expensive one:

1. **Banked evidence stops being one matrix.** A 12-cut matrix whose first six
   cuts ran on one srcversion and whose last six ran on another is not a matrix;
   it is two half-matrices, and any reviewer is right to say so.
2. **A prep can race the linker.** If prep copies `mxfs.ko` while `ld`/`objcopy`
   is still writing it, the srcversion check fails and the arm ABORTs — a lost
   lap with a confusing reason.

## The rule

While any rig lap is running, the tree's `mxfs.ko` is part of the running
experiment. Build kernel changes either before launching the sweep or after it
reports DONE. Source edits to files the lap does not execute are fine; the
module and the harness script being executed are not.

The sibling hazard, already known and the same shape: **never edit a shell
script while a lap is executing it** — bash reads the file incrementally, so an
edit lands mid-execution.

If a build must happen during a lap, build somewhere else — not into the path
prep reads.

---
name: sb-counter-recheck-2026-07-11-live-drift-confirmed
description: SB summary-counter cross-node drift CONFIRMED live on current build (v0.10.61) via direct df -i test; but clean-unmount on-disk state matched chk_mxf…
metadata:
  type: project
tags: [sb-counters, dir_reuse_coherency, gpt-consult-followup, caw]
---

## What was tested (GPT consult item #5 / sess33 lead follow-up)

Fresh mkfs, 32-node CAW cluster (build 65CA8C4E2BAFDA071FC9AF9 = v0.10.61),
using only test1+test2 for a controlled churn test:
- 8 rounds. Each round: test1 creates 60 files in a shared dir, records
  their inode numbers, deletes all 60 + sync. Immediately after (before
  test2 does anything), capture `df -i` on BOTH test1 and test2. Then test2
  creates 60 NEW files, records inode numbers, checks for overlap with
  test1's just-freed set, then deletes its own files + sync.

## Result 1 — CONFIRMED: live in-core cross-node divergence is real

Every single round, at the exact same instant (right after test1's
create+delete+sync, before test2 acts): test1's own `df -i` reported
`IUsed=4 IFree=26165180`; test2's `df -i` on the *same shared filesystem*
reported `IUsed=3 IFree=26165181` — a reproducible, persistent 1-count
discrepancy between two nodes' live in-core views of the same global
inode-usage summary. Identical every round (not growing, not shrinking —
a static baked-in offset, most likely because test1 created the shared
test directory itself and counted that +1 locally while test2's in-core
view never incremented for an op it didn't perform).

This is direct, current-build, non-crash confirmation that the mechanism
sess33 hypothesized (each node's in-core sb_icount/sb_ifree/sb_fdblocks are
independent running totals seeded at mount time, with no cross-node
real-time synchronization) is REAL and PRESENT TODAY, not just a historical
finding from an older build or a post-crash artifact.

## Result 2 — NOT reproduced: no at-rest on-disk drift after a CLEAN unmount

After the churn test, did a coordinated unmount of all 32 nodes (see the
separate mass-unmount-hang note — this took two tries because of a newly
discovered unrelated bug) and ran `tools/chk_mxfs -v` on the device. Result:
**clean** — `fdblocks=13016812 icount=128 ifree=125` in the on-disk SB,
zero ERROR/WARN lines about summary-vs-AG-btree mismatch. This is DIFFERENT
from the original sess33 finding (which saw `sb_ifree=0` vs 1616 actually
free, `icount` off by 128, etc.) — but that finding was captured on a
device that had CRASHED (corrupted by a real bug), not cleanly unmounted.

## Refined hypothesis for whoever picks this up next

The drift is real but appears to be a **transient, live-only** phenomenon
during active multi-node operation, not something that persists into the
at-rest on-disk SB once things go clean/idle — a clean unmount (or
whatever settling happens during it) appears to reconcile it. This is
still exactly the mechanism GPT flagged as dangerous: a node's allocation
decision (reuse an existing free inode vs. allocate a new chunk) is made
against its OWN live (possibly-wrong) in-core view AT THE MOMENT of the
call — it doesn't matter that things eventually reconcile at unmount if a
wrong decision already got made and committed to disk in the meantime
(extra inode-chunk allocation in a contended AG, exactly the concern from
sess33). My 8-round/60-file test was too light to force the dramatic
`ifree≈0` case sess33 saw; a heavier/longer/more-node run (or one that
doesn't let each round cancel out via delete) would be needed to see
whether the live divergence GROWS with sustained cross-node churn instead
of staying at a constant small offset. Did not chase further this session
per user direction to move through the rest of the priority backlog.

## Architectural takeaway (matches GPT's recommendation)

Confirms GPT's advice from the architectural consult
(`gpt-consult-dir_reuse32-architectural-review`) is directionally correct:
don't use the global SB summary as a correctness/allocation gate across
nodes — derive alloc decisions from per-AG authoritative (DLM-coherent)
state instead, since the global summary CAN legitimately diverge live
between nodes even on a healthy, non-corrupted, current-build cluster.

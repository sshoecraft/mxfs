---
name: trap-withholding-the-ag-exhausted-vote-from-own-refusals-hangs-a-create-whose-sole-free-number-is-refused-for-good
description: TRAP (D-DIALLOC-REPICK-STORM, s60): fixing a 24-carve reservation overrun by making swept vote only on peer contention hung the create instead; bound…
metadata:
  type: feedback
tags: [dialloc, allocator, swept, carve, reservation, liveness, d0947]
---

# The AG-exhausted vote is about usable candidates, not about who refused them

## What bit
D-DIALLOC-REPICK-STORM (0.87.22): under a storm where every candidate was refused
transiently (dbg_validate_nomagic_n=200), one create's xfs_dialloc carved 24 inode
chunks against a reservation that pays for one (blk_res 189 -> 5, then
xfs_trans_mod_sb SHUTDOWN_CORRUPT_INCORE, node withdrew). The trigger was the storm
exit setting rs->swept=1, which xfs_dialloc_try_ag answers by carving, on every
re-sweep with the same transaction.

The first fix (s60b/s60c) attacked the VOTE: swept only when the lap saw peer
contention (contended || cool_skips), never for our own pubpend/nomagic refusals.
Result: tests/d0947_nomagic_repick.sh phase 2 (ONE number persistently refused)
hung the create — P-DIALLOC-RESV-SWEPT probes=0 contended=0 cool=0 pubpend=2
swept=0, then P-DIALLOC-SWEEP-RETRY sweep=1088... at 5-300 ms backoff, forever,
with the parent directory ILOCK held; both laps ABORTed at the 120 s measure
budget and test1 had to be power-cycled twice. The refused number was the AG's
only usable free inode, so with no carve there was nothing to converge to.

## The rule
- `swept` means "this lap found no usable candidate" — whoever refused them. It
  must keep being cast by the full cooling/held lap AND by the transient-refusal
  storm exit; a carve is the only source of fresh numbers when the existing ones
  are refused for the life of the mount.
- The reservation is protected by a CREDIT, not by the vote: one carve per
  xfs_dialloc call (mxfs_dialloc_carve_gate, rs->grows), spent after
  xfs_ialloc_ag_alloc succeeds and before the roll; a second carve is refused
  (P-DIALLOC-CARVE-BOUND) and the AG handed back -EAGAIN. Astra's ruling: "this
  funded allocation operation cannot carve a second chunk, regardless of how
  candidate validation behaves" — and the numeric remaining-reservation check is
  NOT a substitute, because the allocator cannot see the directory-entry share.
- Reset rs->swept at every AG visit so one AG's vote never carves in the next.

## General lesson
When a flag feeds two consumers (here: "carve now" and "re-sweep later"), fixing
the consumer that misbehaves by starving the flag also starves the other consumer.
Bound the dangerous action at the action, and leave the signal honest. Verify a
storm fix with the harness's NON-storm phases too: phase 2 is where the vote was
load-bearing, and the storm phase alone would have passed.

## Evidence
- overrun: tests/evidence/20260919T005455Z_d0947nomagic_s60a/dmesg_test1.txt
  (P-DIALLOC-GROW-RES grows=1..24, P-TRANS-BLKRES-OVERRUN blk_res=5 blk_res_used=8)
- hang: tests/evidence/20260919T010505Z_d0947nomagic_s60b/, ..._s60c/ (ABORT phase
  2 rc=124), test1 current-boot journal s60 (1293 storm lines, 540 RESV-SWEPT swept=0,
  0 GROW-RES after phase 1).

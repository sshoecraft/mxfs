---
name: trap-ag-held-answers-one-on-tcp-so-a-repair-gated-on-it-is-caw-only-and-a-tcp-strand-hangs-forever
description: TRAP (s164): mxfs_v5_dlm_ag_held returns 1 on TCP ("don't assert"), so the stranded-AG repair was gated CAW-only and a TCP AG strand stalled peers 40…
metadata:
  type: feedback
tags: [dlm, tcp, strand, ag, trap]
---

# A placeholder answer on one transport silently removes a repair there

`mxfs_v5_dlm_ag_held()` answers the CAW on-disk slot on CAW, but returns a
constant **1 on TCP** ("don't assert") for callers that must never be told a
grant is gone. The stranded-AG repair (P5N-AG-ORPHAN-NAK branch in
xfs/xfs_mxfs_dlm.c) needed a real answer, so it was gated on `is_caw` and on
TCP it logged `disk_held=-1 repair=0` forever.

On TCP the strand lives in the LOCAL GRANT TABLE, not on the platter: a release
that skipped its unlock leaves our own GRANTED entry, and the orphan NAK
(`mxfs_dlm_release_orphan_if_unheld`) refuses with -EBUSY because *any* local
entry blocks it. Measured (probe P-ORPH-NAK-BUSY): `state=2 mode=5 grant_gen=2`,
age growing 10 s per attempt. Peer creates timed out every 61 s for 400+ s and
cascaded into four unrelated suite failures (ag_strand_repair, sustained_load
errs=241, alloc_witness, chk_clean).

Fix (0.89.74): `mxfs_v5_dlm_ag_strand_held()` — slot on CAW,
`mxfs_dlm_settled_grant_nb()` on TCP (1 only when every local entry is
GRANTED; -EBUSY when anything is in flight) — feeds the existing
transport-neutral re-adopt path. Verified: P295-RX-READOPT-MINTED ~20 s after
injection, ag_strand_repair PASS strands=1 repaired=1 (s164c).

## The lessons
- Before trusting a "held?" helper in a repair, check what it answers on EACH
  transport. A constant is not an answer.
- A suite run where four consecutive tests fail with timeouts: look for ONE
  stuck grant first (P-LKTIMEOUT-HOLDER with a growing held_ms) — and check
  for a test-only injector (P200-STRAND-INJECT) before calling it a deadlock.
  The first reading here ("lock-order inversion") was wrong and had to be
  withdrawn from the queue.
- `ag_strand_repair` arms `mxfs.ag_strand_inject=-1` on every node; a strand it
  creates that is not repaired OUTLIVES the test and poisons the rest of the run.

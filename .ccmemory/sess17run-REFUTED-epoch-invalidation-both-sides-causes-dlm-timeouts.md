---
name: sess17run-REFUTED-epoch-invalidation-both-sides-causes-dlm-timeouts
description: sess17(ccloop) REFUTED: epoch-based prior-tenure dir-block invalidation (acquire-side evict OR read-side xfs_da_read_buf) causes ~1900 DLM acquire ti…
metadata:
  type: project
---

## sess17 (ccloop) — epoch-based dir-block invalidation REFUTED (both sides → DLM timeouts)

Built on the KEEP fork-adopt fix [[sess17run-FIX-forkadopt-handoff-round1-fixed-round5-residual]] (build 9AF854E6, round 1→5). Tried to close the round-5 single-entry data-block revert (P13-STALEREAD, daddr-reuse, sameincarn=1, the durable count-clobber family) with the master-epoch prior-tenure signal. BOTH placements FAIL with DLM acquire timeouts:

1. **Acquire-side force-evict** in mxfs_dir_drain_evict_data_blocks: epoch-gated (force-evict in_ail block whose b_mxfs_dir_epoch < valid_epoch) → **2142 acquire timeouts + DATASCAN-HEAL=0 (unhealed leaf holes)**, died round-5 barrier. (Blanket variant — drop undestaged keep unconditionally — REGRESSED round 5→3, 24 entries lost = dropped current-tenure un-drained block.)
2. **Read-side invalidation** via `mxfs_dir_evict_prior_tenure=1` (xfs_da_read_buf:3307-3336, GPT part-2, already-implemented-but-gated, compares b_mxfs_dir_epoch < master `mxfs_v5_dlm_inode_dir_epoch`) → **1938 acquire timeouts + 47 rc=-110**.

### ROOT of the over-fire (confirms sess16 refutation): the MASTER dir epoch advances on EVERY dir modify by ANY node (mxfs_dlm_note_dir_modified at each create). Under the 8-node 800-entry storm that is ~constant, so `b_mxfs_dir_epoch (stamped at last read/modify) < master_epoch` is true on almost EVERY dir-block read → invalidate→cold-read storm → DLM contention → 120s acquire timeouts (RULE-0 fail). The epoch is PER-MODIFY granularity; the coherence boundary needed is PER-HANDOFF (per EX tenure change). grant_gen is per-handoff but edge-triggered → under-fires ~80% on TCP. This granularity mismatch is the core unsolved tension.

### What works WITHOUT over-firing: owner_aba + incarn_aba (always-on in xfs_da_read_buf, fire only on genuine reuse) and the fork-adopt (fires once-per-acquire on grant_gen/epoch handoff). The round-5 residual block is same-owner + same-incarnation + stale-tenure-content, so only the (over-firing) epoch distinguishes it.

### NEXT IDEAS (not yet tried): (a) a PER-HANDOFF epoch that advances only on EX tenure CHANGE (grant_gen), made reliable on TCP (fix the edge-loss in the grant path) rather than per-modify; (b) RELEASE-side: a releasing node invalidates ONLY its own cached dir DATA buffers (bounded, once per release, not per-read) after the drain — fires once per handoff, not per-modify, so no storm. Do NOT retry per-modify-epoch invalidation (refuted, timeouts). Keep 9AF854E6 (fork-adopt) as baseline. Criterion NOT met.</body>

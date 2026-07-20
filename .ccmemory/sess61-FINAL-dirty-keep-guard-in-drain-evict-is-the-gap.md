---
name: sess61-FINAL-dirty-keep-guard-in-drain-evict-is-the-gap
description: sess61 FINAL: the slow-path acquire drain-evict (mxfs_dir_drain_evict_data_blocks ~3983) only evicts !dirty blocks; a DIRTY stale block0 (P61-BLK0: d…
metadata:
  type: project
---

## sess61 FINAL — the dirty-keep guard is the exact code gap

`mxfs_dir_drain_evict_data_blocks` (xfs/xfs_mxfs_dlm.c:3736, called on slow-path
EX reacquire at ~10266 AND from the fast-path stale-refresh at ~9781) evicts a
cached dir block (clears XBF_DONE -> next read FUA-refetches disk) ONLY when:
```
(dbp->b_flags & XBF_DONE) && !pinned && !dirty && !delwri &&
(!in_ail || !mxfs_dir_buf_is_undestaged(dbp))      // line ~3983
```
=> a **DIRTY** block is NOT evicted — it is KEPT and served to the RMW. This is
the SAME dirty-keep guard as mxfs_dir_evict_data_blocks (~2382).

sess61 P61-BLK0 evidence at the clobber: the stale block0 is **dirty=1 inail=0
pin=0 bufgen=0, core_node1=0 while disk_node1=76/84/88** (in-core behind disk).
So a DIRTY, content-behind-disk block0 IS present at modify/acquire time and is
KEPT by this guard, then RMW'd -> peers' dirents durably clobbered.

The code's stated assumption (comment ~3978): "a genuine peer modification
implies WE released EX first, and the release drain (invariant #1) destages our
blocks out of the AIL — at a true peer-modified acquire these conditions never
hold." THIS ASSUMPTION IS VIOLATED in dir_reuse_coherency: a dirty block0 exists
at acquire with content behind disk. WHY is the open question:
  (a) the release-drain did NOT destage/clean this block0 (drain gap), OR
  (b) the block0 became dirty AFTER acquire by an EARLIER create in the SAME wave
      that RMW'd a stale base (so by the converting/clobbering create it is
      already dirty-stale), OR
  (c) the dirty state is from a get_buf+data_init (conversion/grow) that
      materialized block0 empty on a stale base (bufgen=0 = freshly init'd, never
      tenure-stamped) — consistent with the bufgen=0 observation.

### NEXT SESSION — decisive experiment
Instrument WHY the dirty content-behind-disk block0 exists at acquire. At
mxfs_dir_drain_evict_data_blocks, for block0 (daddr of logical 0) when
dirty && content-behind-disk (FUA compare), log: bufgen, incarn, BLI lsn vs
written_seq, who last logged it (caller), and whether a release-drain ran since
the peer's grant. Likely (c): the conversion/grow's data_init created block0 on a
stale base. If so, the fix is at materialization (sess36/sess42 — adopt disk
block0 if it already exists for this incarnation) OR force-drain+reload the dirty
block0 at the genuine-peer-handoff acquire instead of keeping it. Do NOT blindly
evict a dirty buffer joined to the live trans (iflush-corruption shutdown) — must
either drain-then-reread at a safe point (no active trans) or merge.

### Build state for next session
7B1FF03F. grant_gen infra present, fast-path action GATED OFF (mxfs.dirwr) after
it REFUTED (grant_gen over-fires — see
[[sess61-grant-gen-fix-REFUTED-overfires-need-peer-owner-signal]]). Baseline
~2/24 (NOT re-verified post-gating; verify first). Diagnostics P61-BLK0/LBMAP
gated behind mxfs.instr. Run mxfs.instr=1 for the P61-BLK0 disk-vs-incore probe.
See [[sess61-DECISIVE-dirty-bufgen0-divergent-block0-kept-by-dirty-guard]],
[[sess61-HANDOFF-state-and-next-steps]].</body>

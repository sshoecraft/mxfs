---
name: sess69-FINAL-clobber-indistinguishable-from-rm-real-held-ex
description: sess69 FINAL: clobber write holds REAL EX (real_mode=5, mode-aware) — non-owner-flush REFUTED. Paradox: dir buffer 1-behind same-daddr same-incarnati…
metadata:
  type: project
---

## sess69 FINAL — non-owner-flush REFUTED; the clobber holds REAL exclusive EX

Used the MODE-AWARE `mxfs_v5_dlm_inode_held_rawmode` (NOT the mode-blind `mxfs_v5_dlm_inode_held`) in the dataclobber detector (build A6D2BC7B). At the single-entry clobber (`kind=data delta=1`):
- `comm=rm real_mode=5(EX) in_txn=0` ×146 — legit rm removals.
- `comm=xfsaild real_mode=5(EX) in_txn=0` ×4 — THE CLOBBER. **real_mode=5 = the flushing node REALLY holds EX (exclusive).**

So the non-owner-stray-flush hypothesis is **REFUTED**: the clobbering xfsaild dir-block write happens while the node holds genuine exclusive EX. The owner-fence fix (skip writes by held<EX) would NOT catch it.

### The hard paradox (the real remaining root)
A node holds EXCLUSIVE EX (real_mode=5, P-DOUBLEGRANT=0), yet xfsaild flushes a dir DATA buffer with ONE FEWER entry (158) than the CURRENT on-disk block (159) at the SAME daddr, SAME incarnation (bincarn==cincarn). Under exclusive EX only this node can advance disk — so this node itself put 159 on disk, but a buffer with 158 for that daddr still exists and xfsaild flushes it, reverting to 158 and dropping the entry.

Two divergent content versions for one daddr within one incarnation while holding EX ⇒ a **stale lingering / duplicate xfs_buf for a reused daddr**. Most likely mechanisms:
1. **daddr free+realloc within a round**: the dir grows/shrinks (block↔leaf conversion, data-block coalesce/split) so a logical dir block's daddr is freed and reallocated within the same incarnation; the OLD buffer for that daddr lingers in the AIL with a stale BLI (158) while the dir's current image (159) is what was committed; xfsaild later flushes the stale lingering buffer.
2. A **ghost/duplicate buffer**: an evict or invalidation created a second buffer state for the daddr (note: the evict deliberately does NOT xfs_buf_stale to avoid "ghost/duplicate buf cache corruption" — but some other path may).

### NEXT SESSION — decisive instrument (track the clobbered daddr's buffer lifecycle)
At the dataclobber detector, when it fires (buf behind disk, EX-held), ALSO log: the buffer's bli_flags / li_flags (in AIL? li_lsn), b_flags, b_last_holder, and whether the daddr was recently freed/realloc'd (check the AG bnobt or a free/alloc trace for that daddr THIS round). Add a trace at dir-block FREE (xfs_dir2 shrink/da_shrink_inode / bmap free) and ALLOC for the dir inode, logging daddr + incarnation, so a free+realloc of the clobbered daddr within the round is visible. Confirm mechanism 1. If confirmed, FIX: on freeing a dir data block, INVALIDATE (and remove from AIL) any cached buffer at that daddr so a stale lingering BLI cannot be reflushed after the daddr is reused. (This is an alloc/free-side coherency fence, distinct from the DLM-modify fences that have all been tried.)

### Hypotheses now REFUTED this session (don't retry)
phantom-EX, double-grant, split-master, reacquire-evict-incomplete, release-not-durable, reload-skipped, stale-base-detectable, extent-map-divergence, write-side count-suppression (catastrophic), non-owner-flush (real_mode=EX). The clobber is a stale LINGERING/DUPLICATE buffer for a reused dir-block daddr, flushed while the node legitimately holds EX.

Build A6D2BC7B (baseline + dirwr-gated detector enhancements; inert at production dataclobber=0/dirwr=0). Diagnostic config: `MXFS_EXTRA_MODARGS='dataclobber=1 dirwr=1' MXFS_TEST_ENV='DRC_ROUNDS=20 DRC_STREAM=1' ./run.sh 4 tcp dir_reuse_coherency`. test3 had a wedged mxfs-ino-bast kworker mid-session → recovered via `virsh -c qemu:///system destroy/start test3`. Marker NOT written — criterion NOT met. See [[sess69-ROOT-xfsaild-reflush-stale-dir-buffer-behind-disk]].</body>

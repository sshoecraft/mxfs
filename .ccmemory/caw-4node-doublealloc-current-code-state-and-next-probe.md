---
name: caw-4node-doublealloc-current-code-state-and-next-probe
description: 4/caw double-alloc: release-side bnobt/cntbt hard-barrier IS present (P117 evict clean+drained at yield) but insufficient. intra-vs-cross UNRESOLVED…
metadata:
  type: project
---

## 4/caw double-alloc — current-code state + the decisive next probe (sess3, build 0510FC3E)

Continues [[caw-4node-cache_coherency-ROOT-bnobt-doublealloc-NOT-prfence]]. The 4/caw
cache_coherency FAIL = daddr double-alloc (dir block clobbered by file data → CRC → shutdown).

### Current code ALREADY has the release-side bnobt/cntbt HARD-BARRIER (and it's insufficient)
`mxfs_dlm_ag_drain_meta_buffers` (xfs/xfs_mxfs_dlm.c:23405) at AG YIELD:
- CLEAN bnobt/cntbt → `xfs_buf_stale`+clear DONE (P117-AGMETA-STALE-CLEAN, line 23517).
- DRAINED (in-AIL/pinned) bnobt/cntbt → `xfs_bwrite` then `xfs_buf_stale`+clear DONE
  (sess99 PUBLISH-AND-DISCARD, line 23682).
- **sess118 REVERTED** extending evict to AGF/AGFL/AGI/inobt/finobt — that desyncs AGF
  freeblks/longest from the btrees and REINTRODUCED the double-free. So evict scope = bnobt/cntbt.
- Acquire-side: fresh CAW-grant path calls `mxfs_ag_meta_coldread_discard(pag,true)` (line 23074).

So both the acquire coldread AND the release bnobt/cntbt evict-at-yield are present. The
double-alloc STILL happens → the hole is NOT in this fence as-scoped.

### NEW evidence this session (build 0510FC3E, pure keeper, mpatha, cache_coherency 0/4)
- Each node double-allocs in ITS OWN AFFINE AG: test1(slot0)→AG0 daddr72; test2(slot1)→AG1
  daddr2093296; test3→AG3; test4→AG2. The daddr-72 block held the `.cache_coherency` (ino131)
  block-fmt dir; test1 re-allocated it for node1.txt DATA via **delalloc writeback** (P-DBLALLOC
  `agno=0 agbno=9 daddr=72 holds=dir-block XDB3 tenure=1 node=0 wasfromfl=0 comm=kworker/u12:3`).
- test2's reader view: `ino=131 fmt=2 nx=1 dir_gen=16 dlm_mode=5(EX)`; P68-EVDECIDE at daddr72
  shows `b_epoch=6 < valid_epoch=7 cur_mep=7` (buffer one epoch behind but undurable=0 → KEPT).
- No P93/P124 REVERT fired on test1; no logged free of agbno9. BUT the P10-INSTR ACQ-FRESH /
  yield probes are GATED behind dirwr/instr (I ran neither) → "0 AG0 yields" is NOT proven,
  the probe was simply OFF. **intra-node vs cross-node is UNRESOLVED.**

### The decisive question the fix hinges on
Is daddr72 a LIVE double-alloc (both dir+file live simultaneously → bnobt gave it twice) or a
FREED-then-reused block whose peer extent-map/dir-inode is stale? And is the 2nd alloc intra-node
(test1 gave daddr72 twice within one AG0 tenure) or cross-node (peer allocated dir, test1 the file)?

### NEXT (RULE 4, LIGHT un-gated probe — instr=1 is 100x slower and HIDES the race, sess30)
Add an un-gated probe scoped to `pag_agno==0 && agbno<64` (cheap, few blocks): at alloc-return
log {agbno,len,owner,node-slot,ag_dlm_tenure_id,wasfromfl,comm}; at `xfs_free_ag_extent` the same.
Catches BOTH the dir-block alloc AND the file alloc AND any free between AND the tenure at each
(same tenure across both = intra-node no-yield; differing = a yield happened). Then re-run 4/caw
cache_coherency, grep daddr=72/agbno=9. This resolves intra-vs-cross and live-vs-freed → picks the
fix. Only THEN consider a Fable consult (RULE 5) with the resolved mechanism.

### Config note
Default `dir_force_block=1` (xfs_mxfs_dlm.c:7908) makes cache_coherency dirs block-format →
allocate dir blocks → exposes this. Do NOT "fix" via force_block=0 (breaks dir_reuse; config
tension, not a fix). dirwr/dirland are DIAGNOSTIC probes (default 0), NOT correctness knobs.
</body>

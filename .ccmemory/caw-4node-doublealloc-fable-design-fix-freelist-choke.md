---
name: caw-4node-doublealloc-fable-design-fix-freelist-choke
description: Fable design for 4/caw double-alloc: root=delalloc-writeback alloc (xfs_alloc_vextent_start_ag wrapper) bypasses AG-DLM fresh-grant coldread → reads…
metadata:
  type: project
---

## Fable design (RULE-5 consult, sess3, 2026-07-07) — 4/caw double-alloc fix

Consulted after complete instrumented diagnosis (file data aliases the `.cache_coherency`
block-fmt dir block at daddr72=agbno9 → dir3 CRC → shutdown → 0/4). See
[[caw-4node-cache_coherency-ROOT-bnobt-doublealloc-NOT-prfence]]
[[caw-4node-doublealloc-current-code-state-and-next-probe]].

### ROOT (Fable, ~85% — mechanism (a)), KEY INSIGHT
**agbno 9 = the leftmost record of a PRISTINE post-mkfs bnobt** (agbno 0-8 = sb/agf/agi/agfl/
bnobt/cntbt/inobt/finobt/refcountbt roots). Deterministic collision at agbno9-in-every-affine-AG
⇒ the FILE allocator worked from the PRISTINE LUN bnobt snapshot (the dir's alloc never in its view).
In XFS 6.19 `xfs_alloc_ag_vextent()` is NO LONGER one funnel — split into 5 wrappers
(xfs_alloc_vextent_{this_ag,exact_bno,near_bno,start_ag,first_ag}) → all converge on
`xfs_alloc_vextent_prepare_ag()` → `xfs_alloc_fix_freelist()` → `xfs_alloc_ag_vextent_{exact,near,size}`.
- DIR block alloc (mkdir→xfs_da_grow_inode→bmapi_write→bmap_btalloc): near/exact_bno.
- FILE data alloc (kworker writeback: xfs_bmapi_convert_delalloc→bmapi_allocate→bmap_btalloc,
  FRESH trans first alloc): **xfs_alloc_vextent_start_ag()** — DIFFERENT wrapper/chain.
My P-AGLOW probe caught the dir alloc but NOT the file alloc ⇒ the AG-DLM acquire/fresh-grant
coldread hook likely lives in a placement family that this wrapper misses ⇒ kworker read bnobt COLD
from LUN with no fresh_peer coldset while the dir creator STILL holds AG EX (no yield ⇒ no Inv-1
drain ⇒ LUN bnobt pristine) ⇒ saw agbno9 free, took it, data bio landed on daddr72.
- (a′) even when DLM taken: fences evict bnobt/cntbt but NOT AGF; acquire coldread re-reads bnobt
  blocks but may walk from a CACHED stale AGF root/stats (bites aged FS).
- (b) AGFL/bnobt desync: IMPOSSIBLE — file data never comes from AGFL (AGFL only feeds btree-block
  splits). (c) stale file buffer reflush: REFUTED — file data is page-cache/iomap bios not xfs_buf,
  and no free+realloc happened. (d) concurrent-EX CAW CAS: ~10%, not deterministic, keep falsifiable.
- P-BLKWR=0: dir3 buf dirty/pinned in creator CIL/AIL; peer FUA-reads daddr72, hits file data,
  shuts down BEFORE xfsaild wrote dir buf. Downstream symptom. BUT verify inode-DLM release drain
  doesn't SKIP PINNED buffers (silent Inv-1 violation).

### THE FIX (Fable Q3), landing order
1. **CORE: move AG-DLM acquire + fresh-grant coldread to the single choke `xfs_alloc_fix_freelist()`**
   (and `xfs_free_extent_fix_freelist` for free). Every wrapper + every iterate_ags AG + every retry
   passes through it, IN THE ALLOCATING TASK'S OWN CONTEXT (mkdir, kworker, xfsaild). Add
   `WARN_ONCE(!mxfs_ag_dlm_held(pag), ...)` tripwire in fix_freelist. Avoids lock-inversion: DLM
   acquired by the task about to lock AGF b_sema = DLM-before-AGF, same context; use `tp->t_highest_agno`
   for ascending-order multi-AG acquisition (inherits XFS AB-BA prevention). With the tripwire invariant,
   BAST-drain waits become well-founded (any un-trylockable buf belongs to a live local txn that owns
   the DLM and commits without blocking on acquire) → bounded wait not cycle.
2. **Acquire-side AGF/AGFL REFRESH (not release evict):** on fresh_peer grant (Inv-1 ⇒ no dirty AG
   state), lock AGF/AGFL, clear XBF_DONE, FUA re-read (same op that discards bnobt/cntbt) → one coherent
   cold snapshot/tenure. Closes (a′)+AGFL WITHOUT the sess118 AGF-desync (that was RELEASE-side evict).
3. **Don't skip PINNED in release drains:** pinned → xfs_log_force_lsn(b_lsn) → wait unpin → xfs_bwrite.
4. PAL: yield = drain writes → SYNCHRONIZE CACHE (or FUA writes) → CAW release (so peer fresh-grant FUA
   read sees drained image, not a target destage race).
NOT needed: per-daddr gen stamps, write-side interlocks (refuted), dir_force_block toggle (leave =1).

### VERIFY FIRST (RULE 4) before implementing #1
Check current code: is `mxfs_ag_dlm_lock` already in `xfs_alloc_fix_freelist` (xfs_alloc.c:3981/3983)?
If yes, all wrappers DO acquire AG-DLM there → then the hole is the fresh_peer/coldread NOT firing on
the start_ag/writeback path (a′-like), not "no DLM at all". Confirm with Probe: at fix_freelist log
{agno,agbno-target,entry_wrapper,USERDATA,dlm_held,fresh_peer,coldread_ran,bnobt_leftmost_rec,
AGF_cachehit}. dlm_held=0 → (a); held+stale-AGF-fingerprint → (a′). Then implement the matching fix.

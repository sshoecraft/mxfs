---
name: sess22-ccloop-inv2-fresh-acquire-coldread-hole
description: sess22(ccloop): PROVEN bnobt double-free root = genuine fresh CAW-grant path never calls mxfs_ag_meta_coldread_discard, so stale in-AIL bnobt/cntbt s…
metadata:
  type: project
---

# sess22 (ccloop 4eef1f39) — bnobt double-free ROOT proven + Inv-2 fix in progress

## DIRECTIVE (user, this session): implement the cache-coherency RE-ARCHITECTURE
(the Grok+Gemini+Claude fence design, [[cache-coherency-rearch-provenance-and-gap]]),
NOT more write-side band-aids. P122/P124 write interlocks are a DEAD END — P124
generalized suppression REGRESSED cache_coherency to 0/4 + new "Corruption of in-memory
data" shutdown (xfs_buf.c:1887): refreshing one bnobt buffer desyncs sibling cntbt/AGF
(sess118 lesson). Suppression REVERTED to log-only this session.

## PROVEN ROOT (RULE-4, decisive test4 timeline, build C91DECFC)
The bnobt double-free is an **Inv-2 acquire-invalidation-fence FAILURE**, NOT exclusion
divergence:
- New probe **P125-AG-DIVERGE** (xfs_buf.c, compares in-core-held vs on-disk
  mxfs_v5_dlm_ag_held) fired **0×** → at the stale write we DO hold the AG on-disk.
  Exclusion-divergence REFUTED.
- test4 dmesg, agno=3: `P10 ACQ-FRESH` (genuine fresh CAW grant) → invalidate STALED
  agf+agi (P14) **but NOT the in-AIL bnobt/cntbt** at daddr 6261968/6261976 →
  `P74 cnt-modify-on-STALE-buf cnt_gen=0 pag_gen=1` → `P124 ALLOC-REVERT` xfsaild writes
  bnobt nr=2 over COHERENT disk_nr=1 (peer's durable alloc) = the revert clobber.

## THE HOLE (code-confirmed, xfs/xfs_mxfs_dlm.c)
The THREE reclaim acquire paths (release_pending / cached / release_pending-2, ~6722/
6781/6804) call `mxfs_ag_meta_coldread_discard`. The **genuinely-fresh CAW-grant path**
(after `mxfs_v5_dlm_ag_lock` ~6921; the P102-ACQ / disk_gen block ~6945-6991) bumps the
shared epoch + clears AGF_INIT/AGI_INIT (→ agf/agi re-read) but **NEVER calls
coldread_discard** → cached bnobt/cntbt are not bulk-invalidated. AND coldread's in-AIL
branch skipped bnobt/cntbt when `mxfs_buf_is_undestaged()` (misclassified a lingering
prior-tenure in-AIL buf as this-node-ahead).

## FIX IN PROGRESS (build C2AD9E9D — COMPILES, consistent, NOT yet behaviorally complete)
Edits landed:
1. `mxfs_ag_meta_coldread_discard(pag, bool fresh_peer)` — new arg (def + proto in
   xfs_mxfs_dlm.h:225 both updated).
2. Both in-AIL bnobt/cntbt branches: discard when `(fresh_peer || !undestaged)`. On a
   genuine peer handoff Inv-1 guarantees no legit this-node-ahead AG-meta, so a lingering
   in-AIL bnobt/cntbt is provably stale → discard unconditionally. Worst case (Inv-1 was
   violated) = space leak, recoverable, NOT a double-free shutdown.
3. The 3 reclaim sites pass `false` (Inv-1 NOT run there → keep conservative undestaged
   guard; sess19b warning).
Diagnostics added (xfs_buf.c): **P124-ALLOC-REVERT** (log-only, proves the producer) +
**P125-AG-DIVERGE** (permanent Inv assertion, currently 0 = good). Both regate to
mxfs_idbg before ship.

## NEXT SESSION — ONE EDIT then test (high-confidence)
1. Add `mxfs_ag_meta_coldread_discard(pag, true);` on the FRESH CAW-grant path, AFTER
   `pag_dlm_lock` is released (the gen block does mutex_lock(&pag->pag_dlm_lock) ~6950;
   find its matching unlock and call coldread AFTER it — coldread requires NO pag DLM lock
   held). Gate on disk_gen having advanced (peer touched the AG) to keep the
   uncontended fast case cheap, OR call unconditionally on every fresh grant (simpler;
   cost = one cache walk).
2. `make modules` → power-cycle ALL 4 (virsh -c qemu:///system destroy+start, 60s) →
   `bash tests/reset4.sh 4` → confirm srcversion on all 4 → `dmesg -C` all →
   `tests/criteria/cache_coherency.sh --nodes 4`.
3. Expect: P124-ALLOC-REVERT → 0, no ltbno/double-free shutdown. If bnobt clobber gone,
   move to the remaining dimension (cross_visibility SLOW / rename empty-content).
4. If P124 still fires: the stale buf either (a) isn't in cache at the fresh-grant walk
   (re-cached AFTER coldread by a concurrent read — then need the read-path hook to also
   honor fresh epoch), or (b) the acquire was a reclaim path not the fresh path (add a
   probe logging WHICH path + agno). 
Cluster currently: build C91DECFC deployed, test4 shut down (needs full reset4).
Related: [[cache-coherency-rearch-provenance-and-gap]] [[sess19b-shared-epoch-design]]
[[sess121-bnobt-clobber-writeside-fix]] [[sess96_gpt_fix_design]] (Inv-1/2/3)

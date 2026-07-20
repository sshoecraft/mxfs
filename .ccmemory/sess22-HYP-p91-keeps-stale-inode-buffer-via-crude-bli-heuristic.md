---
name: sess22-HYP-p91-keeps-stale-inode-buffer-via-crude-bli-heuristic
description: sess22 strongest fix hypothesis: P91-RELOAD-PROTECT keeps a STALE in-core inode-cluster buffer because mxfs_buf_has_uncheckpointed_mods returns true…
metadata:
  type: project
---

## sess22 strongest concrete hypothesis for the stale-inode/bmap root

`mxfs_buf_has_uncheckpointed_mods(bp)` (xfs/xfs_mxfs_dlm.c, the P91-RELOAD-PROTECT gate, used at xfs_mxfs_dlm.c:5878 in mxfs_dlm_reload_inode AND xfs_icache.c:427/1239) returns **true** whenever: pinned, OR `!list_empty(&bp->b_li_list)`, OR a BLI is attached AT ALL ("BLI attached at all → a transaction touched this buffer → return true"), OR _XBF_DELWRI_Q.

This is the **exact contradiction sess120 documented** for AG-meta buffers but here applied to the **INODE cluster** buffer: the BLI-attached flag cannot distinguish
- (A) drained pre-yield, content ON disk, BLI merely lingers in the AIL until the next checkpoint → **safe to adopt disk**, vs
- (B) un-destaged, content NOT on disk → must keep in-core.
The function conservatively returns true for BOTH, so the reload KEEPS the in-core cluster buffer (kept_protected=true; no xfs_buf_stale, no XBF_DONE clear) and does NOT adopt the coherent on-disk dinode. If the kept in-core inode is a STALE incarnation (prior life's bmap, but a lingering BLI), the reload no-ops and the **stale extent map (bmap) survives** → block-resolve reads a reused daddr (dir_reuse_coherency: ino 131 → daddr 0x78 → file data → EFSBADCRC). Matches P47/P81 evidence (in-core gen one behind disk; incore-extent-stale).

### Fix direction (subtle, high-risk — verify before shipping)
sess120 already built the correct discriminator for AG-meta (li_lsn vs the write-verifier-stamped payload_lsn: pinned→un-destaged; in-AIL && li_lsn>payload_lsn→modified-since-write→keep; else drained→adopt). The INODE path needs the analogous coherent discriminator: when reloading and the in-core cluster buffer only has a LINGERING BLI (drained, on disk) AND a coherent PLAIN-bio read of the on-disk dinode shows a DIFFERENT/advanced incarnation (di_gen) than in-core, ADOPT disk (the in-core is a stale ghost), do not keep. MUST NOT regress: a genuinely un-destaged same-EX-tenure dirty inode (this node's real uncommitted work) must still be KEPT (else lost-update). Discriminator must be exact. RULE 4: instrument first — at the P91-keep site for a DIR, plain-bio read on-disk di_gen and log if it differs from in-core i_generation while P91 keeps it (proves the hole).

### Status
A workflow (wf_4035945c-2a0 / wdur6o86j) is adversarially analyzing this exact reload-reset path + 3 others; cross-check its verified candidate against this hypothesis. Cluster rebooted clean & ready. Build in tree: 4F45F442 (FIX1 torn-SF skip + FIX2 data-scan fallback). See [[sess22-CONSOLIDATED-criteria-is-full-suite-root-is-stale-inode-bmap]].
</body>

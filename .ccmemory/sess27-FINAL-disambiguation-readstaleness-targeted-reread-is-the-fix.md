---
name: sess27-FINAL-disambiguation-readstaleness-targeted-reread-is-the-fix
description: sess27(ccloop) FINAL: the dir-slot collision is READ-STALENESS (not durability) — the victim's RELFLUSH (sync bwrite) made node5_f46.md5 platter-dura…
metadata:
  type: project
---

## sess27 FINAL — disambiguated: it's READ-STALENESS at the clobberer's addname; the targeted fix

### Disambiguation (from existing dirwr capture, NO new run needed)
Timeline at daddr=10466208 off=1280 (round 7, lost node5_f46.md5):
- t=112.555753 **P-RELFLUSH** (node5): block flushed via SYNCHRONOUS xfs_bwrite WITH node5_f46.md5 present → node5_f46.md5 is PLATTER-DURABLE at 112.555.
- t≈112.56-112.569: node7 adds node7_f47.md at the SAME off=1280 (its in-core bestfree offered it free).
So the victim's entry WAS durable on the platter BEFORE the clobberer picked the slot. The clobberer (node7) served a STALE CACHED data block (missing node5's add) — a read-coherency miss, NOT a durability gap. The node5→node7 handoff failed to bump node7's i_dlm_dir_gen, so node7's cached block (b_gen==dir_gen) was served fresh by the xfs_da_read_buf hook.

### THE FIX (high confidence, implement+test next session)
TARGETED coherent re-read of ONLY the data block the addname is about to modify, at xfs_dir2_node_addname_int (xfs/libxfs/xfs_dir2_node.c ~1959, the `xfs_dir3_data_read(... dbno ... &dbp)` for an EXISTING block), for a multinode shared dir:
- Before/at the read, if the cached buffer for this daddr is CLEAN (XBF_DONE, !dirty, !in_ail, !pinned, !delwri — i.e. NOT this node's own in-tenure work), force it coherent (clear XBF_DONE|_XBF_FUA_FRESH so the read FUA-refetches the platter), then xfs_dir2_data_freescan to rebuild bestfree.
- Gate: multinode, published shared dir (not i_dlm_unpublished), not single-node. NEW param e.g. dir_addname_coherent_read default 0 for A/B.
WHY this is safe where force_coherent=1 was NOT: force_coherent re-reads EVERY dir block on EVERY read, including blocks whose committer's write isn't durable yet → premature revert (readdir got WORSE, 788). This fix re-reads ONLY the one block the EX holder is about to addname into, and ONLY when clean — the victim's add to that block is already durable (proven above), so no premature revert. Scoped, not blanket.

### Alternative/complementary: fix the missed handoff gen-bump (node5→node7) so node7's cached block is invalidated at read time anyway — investigate why dir_gen didn't bump (dlm.c dg_grant_ex master epoch for ino=131 on rapid same-pair grants; FASTEX-EPOCH fired 0x in round 7). But the targeted re-read is more robust (doesn't depend on handoff-detection reliability).

### Existing site context: xfs_dir2_node_addname_int already has the sess22 P22-FREESLOT-STALE repair (freeindex-vs-incore-bestfree) at lines 1986-2012 — but it does NOT catch a stale bestfree that offers an occupied-on-platter slot (the collision). The new re-read closes that. Build 965BDBD3, working modargs dir_gen_per_handoff=1 dir_modify_extent_adopt=1. See [[sess27-SMOKINGGUN-intrablock-slot-collision-off1280-node7-overwrites-node5]] [[sess27-SYNTHESIS-slot-collision-needs-durability-ordering-not-more-rereads]] [[sess27-HANDOFF-head-state-and-next-step]].

---
name: sess20-reload-selfskip-format-adoption-gap-next-locus
description: sess20 NEXT-LOCUS: the cross-node dir format divergence likely comes from mxfs_dlm_reload_inode (xfs_mxfs_dlm.c:5547) self-skip guards returning earl…
metadata:
  type: project
---

## sess20 (ccloop 8ddb16a2) — NEXT FIX LOCUS for the cross-node dir FORMAT divergence [[sess20-REFRAME-reuse-bug-is-cross-node-dir-format-divergence]].

## mxfs_dlm_reload_inode (xfs_mxfs_dlm.c:5547) is the dir inode reload on cross-node DLM acquire. It CAN rebuild the data-fork format+extent map (xfs_idestroy_fork + xfs_inode_from_disk, the part that would adopt a peer's block->leaf conversion). BUT a stack of SELF-SKIP guards (sess36/49/58/59/8) returns early — keeping the STALE in-core inode (and its STALE FORMAT) — when:
  `!mxfs_dir_disk_superset && i_itemp && (IN_AIL || DIRTY || ili_fields || pincount>0)`
where `mxfs_dir_disk_superset = S_ISDIR && (post_release || peer_modified_since_load)` and
`peer_modified_since_load = S_ISDIR && !i_mxfs_self_created && i_dlm_dir_gen > i_dlm_dir_loaded_gen`.

## HYPOTHESIS (to test next, RULE 4): under dir_reuse_coherency, a node re-acquires the dir EX on the FASTEX path (post_release=false) with its own create still in-flight (pin/in_AIL), and `peer_modified_since_load` is FALSE at that moment (gen not yet advanced past loaded_gen for the peer's FORMAT conversion, or i_mxfs_self_created set on the dir creator/rank1) -> reload SELF-SKIPS -> i_df FORMAT not rebuilt -> node keeps block-format while peer is leaf-format (or vice versa) -> incompatible RMW at same daddrs -> durable cross-node ENOENT + verifier-fail shutdown.

## CONFIRM FIRST (instrument, do NOT patch yet):
1. In mxfs_dlm_reload_inode, log EVERY dir reload decision for ino 131: post_release, i_df.if_format (in-core BEFORE), the on-disk dip->di_format (peek dip after imap_to_bp), i_dlm_dir_gen, i_dlm_dir_loaded_gen, i_mxfs_self_created, in_AIL/dirty/pin, and whether it SELF-SKIPPED. Run dir_reuse_coherency. Look for a reload where in-core format != on-disk format but the reload SELF-SKIPPED (kept the stale format) — that is the proven gap.
2. Also check: does a peer's xfs_dir2_block_to_leaf / sf_to_block conversion bump the shared i_dlm_dir_gen so peers see dir_gen>loaded_gen? (The gen is bumped on slow-path acquire at xfs_mxfs_dlm.c:8474, and on peer-commit notify — verify a FORMAT change triggers it.)

## LIKELY FIX: make the reload self-skip NOT apply when the on-disk format differs from in-core (a format transition is never a "our in-flight mods are fresher" case — adopt the peer's format), OR force a format/extent reload on any dir EX acquire where the on-disk di_format != in-core if_format. CAUTION (sess36): a SAME-TENURE in-flight dir-grow must still keep its own un-drained extents — scope the format-adopt to post_release OR genuine on-disk-format-differs.

## Build at boundary: E98F295F (full P-LEAFWRITE trace; readahead-disable kept; P20 removed). Reliable safe repro: ./run.sh 2 tcp dir_reuse_coherency (row 13, FAIL from ~round 16, node2 entries). Criterion marker CLEARED (NOT met). Official 16-test core still 16/16. [[sess20-reuse-leafhash-ruled-out-hypotheses]]

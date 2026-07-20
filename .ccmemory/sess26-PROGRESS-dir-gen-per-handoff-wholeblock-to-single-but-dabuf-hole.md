---
name: sess26-PROGRESS-dir-gen-per-handoff-wholeblock-to-single-but-dabuf-hole
description: sess26(ccloop) PROGRESS: dir_gen_per_handoff=1 (uncap the fast-path epoch gen-bump so i_dlm_dir_gen advances on EVERY handoff, not once/reload) REDUC…
metadata:
  type: project
---

## sess26 — dir_gen_per_handoff: whole-block loss FIXED, single-entry residual + extent-map hole

### Root of the capped-bump bug (PROVEN)
The fast-path EX-grant epoch-handoff gen-bump (sess64 `mxfs_dir_epoch_adopt=1`, xfs_mxfs_dlm.c ~12119/12156) is CAPPED by `if (i_dlm_dir_gen <= i_dlm_dir_loaded_gen) i_dlm_dir_gen++`. After a reload sets loaded_gen=dir_gen, the FIRST handoff bumps dir_gen=loaded_gen+1, but the 2nd..Nth intra-round fast-path handoffs fail the cap (`loaded+1 <= loaded` false) → NO further bump → cached blocks stay `bgen==dir_gen` and alias a peer-superseded image as fresh. This is the PROVEN `bufgen==dirgen==379` whole-block clobber (sess26 dataclobber=1 run lost node2_f13-32.md5 = one whole DATA block).

### FIX (gated lever `dir_gen_per_handoff`, DEFAULT 0, build 965BDBD3)
Uncap the bump: `if (mxfs_dir_gen_per_handoff || dir_gen<=loaded_gen) dir_gen++` at BOTH fast-path sites (grant_handoff + epoch_adopt). Now i_dlm_dir_gen advances on EVERY cross-node handoff → read-path pre-read invalidation (bgen<dir_gen, xfs_da_btree.c:3363) fires every handoff. SAFE: master epoch advances only on real cross-node handoff, never while we hold EX continuously (no spurious mid-tenure re-read).

### RESULT (8/tcp dir_reuse, clean reboot)
- **Loss reduced whole-block (~20 entries) → SINGLE-entry** (readdir=799 rounds 11,21; ran all 24 rounds). Big improvement — the per-handoff invalidation fixes the dominant whole-block clobber.
- **SIDE EFFECT: 511× `!(flags & XFS_DABUF_MAP_HOLE_OK)` internal error (xfs_da_btree.c:2876)** — per-handoff re-reads now visit dir offsets BEYOND this node's STALE in-core data-fork EXTENT MAP (a peer grew the dir block count; the gen-bump refreshes block CONTENT but not the extent map / if_nextents). Non-fatal (run completed) but trips `dmesg_clean`. Slower: 497s (more re-reads).

### NEXT (RULE-4)
The single-entry residual + DABUF_MAP_HOLE are likely BOTH the stale EXTENT MAP: per-handoff content-refresh without extent-map refresh. Options: (a) on epoch handoff, also reload the data-fork extent map (the existing `dir_ex_stale_refresh`/`dir_modify_extent_reload` levers — check why the fast-path handoff sets dir_ex_stale_refresh but the extent map isn't reloaded); (b) restrict the per-handoff invalidation to DATA blocks only (exclude leaf, which is where DABUF_MAP_HOLE bites — like dir_fua_refresh_destaged data-only) AND separately refresh the extent map. Test dir_gen_per_handoff=1 + dir_modify_extent_reload=1 next. Build 965BDBD3 = keeper + dir_gen_per_handoff default 0 (inert) + prior sess26 inert levers. [[sess26-dataclobber-detector-catches-only-legit-removes-creastage-loss-invisible]]

---
name: sess2-ccloop-leaf-DATA-epoch-fix-works-residual-now-leaf-HASH-hole
description: sess2(ccloop) build B1ECB092: added epoch-refresh to leaf/block addname DATA-block read (coherent_refresh). At DEFAULT mht=300 (baseline=0/8 determin…
metadata:
  type: project
---

## sess2 — leaf/block DATA-block epoch refresh: WORKS (data side), residual moved to LEAF-HASH side

### Fix (build B1ECB092): added the node-format master-handoff-epoch gate to `mxfs_dir_addname_coherent_refresh` (xfs_dir2_data.c, called by leaf:1262 + block:448 + node:2008). When b_mxfs_dir_epoch < master dir-epoch (a peer held EX since this DATA block's base loaded), force the caller's cold re-read so the free-slot search reflects the peer's tenure. CLEAN-only (own work never dropped). Gated mxfs_dir_addname_epoch_refresh (default 1). Plus P2-EPOCHPLACE always-on probe (xfs_dir2_data.c, regression detector).

### Result at DEFAULT mht=300 (baseline here = 0/8 DETERMINISTIC corruption+shutdown):
**2/3 PASS** (wall 450-453s passes / 584s fail). The DATA-side free-slot double-alloc is FIXED: the failing iter now has **readdir=800/800 (count CORRECT)** — no missing dirents. P2-EPOCHPLACE stale_base dropped to ~0-1 (was 11+). So the leaf/block DATA epoch refresh closed the intra-block double-alloc at default mht (no slow batching needed → good for RULE-0).

### Residual MOVED to the LEAF-HASH side (round 8): `lastfail readdir=800/800 lookup_fail=1 missing=[node6_f39.md5]` on ALL nodes. = node6_f39.md5's DATA dirent exists (readdir lists it) but its LEAF hash entry is MISSING (lookup ENOENT) = leaf-index ↔ data divergence. Then test1 (rm node) hit DABUF=4 + shutdown=1 walking the leaf-inconsistent dir. P2-LEAF-EPOCHSTALE fired only 1× (data-side now rare). So the remaining bug is the LEAF BLOCK (hash index) lost-update: a node's leaf-hash insert used a stale/superseded LEAF block (the leaf block read in xfs_dir2_leaf_addname is NOT epoch-protected — only the DATA block now is).

### NEXT (RULE 4): epoch-protect the LEAF block read in xfs_dir2_leaf_addname (and the node-format leaf blocks, and lookup). The leaf buffer `lbp` (xfs_dir3_leaf_read early in leaf_addname) must be cold-re-read when its b_mxfs_dir_epoch < master_ep before the hash entry is inserted — same idiom as the data-block fix. The xfs_da_btree.c:3393 read-path epoch gate (epoch_stale/tenure_stale) ALREADY does this for ALL dir blocks incl leaf, but is gated OFF (mxfs_dir_evict_prior_tenure=0, mxfs_dir_tenure_evict=0 — they over-evict DATA→readdir=0). OPTION: enable that gate for LEAF/NODE/FREE buffer types ONLY (not DATA — data is now handled by the addname-level fix), since re-reading a pure index block is safe. OR add an explicit leaf-epoch refresh in leaf_addname before the hash insert.

### Build B1ECB092 = EA485CE6 + P2-EPOCHPLACE probe + leaf/block DATA epoch refresh. KEEP (improvement). Criterion NOT met (2/3, leaf-hash residual). Timing ~450s still RULE-0-slow but no longer needs mht=1500.
See [[sess2-ccloop-ROOT-PROVEN-leaf-block-addname-missing-epoch-refresh]] [[sess2-ccloop-mht1500-residual-is-clean-round1-single-dirent-loss-no-corruption]] [[sess22-FIX-node-format-datascan-leafhash-heal]]

---
name: sess22-FIX-node-format-datascan-leafhash-heal
description: sess22(ccloop) FIX build EFBB9861: extend leaf-hash-hole READ heal (mxfs_dir2_datascan_lookup) to NODE/BTREE-format dirs + wire into xfs_dir2_node_lo…
metadata:
  type: project
---

## sess22 (ccloop) — node-format leaf-hash-hole READ heal. Build EFBB9861B5CB420552AB864. KEEP.

### Gap found:
The leaf-hash-hole read heal (mxfs_dir2_datascan_lookup — scans coherent DATA blocks when the leaf hash misses) was wired ONLY into single-leaf `xfs_dir2_leaf_lookup` (xfs_dir2_leaf.c:1814) AND the function itself bailed on any non-EXTENTS fork (`if fmt != EXTENTS return -ENOENT`). dir_reuse's 800-entry shared dir grows to NODE/BTREE format → its leaf-hash hole was COMPLETELY unhealed → stat ENOENT on a present file → test `leaf-hash lookup_fail`.

### FIX (3 edits, all xfs/libxfs/):
1. xfs_dir2_leaf.c: relax the format bail in mxfs_dir2_datascan_lookup — allow BTREE fork when extents are loaded (`!xfs_need_iread_extents`); only bail for shortform/local or unloaded-BTREE. The scan body already reads data blocks via bmap (xfs_dir2_db_to_da) + walks i_df extents = BTREE-safe. Made the fn non-static.
2. xfs_dir2_priv.h: declare `int mxfs_dir2_datascan_lookup(struct xfs_da_args *)` under __KERNEL__.
3. xfs_dir2_node.c: on `xfs_da3_node_lookup_int` -ENOENT (after releasing all btree/leaf/data buffers, multi-node only), `return mxfs_dir2_datascan_lookup(args)`. Added `#include "../../dlm/v5_mount.h"`.

### RESULT (8/tcp dir_reuse, build EFBB9861, leaf_rebuild OFF):
- 143/145, **NO lookup_fail face** (eliminated), NO shutdowns. P22-DATASCAN-HIT fires when an entry IS in data but missing from leaf (heal). P26-DSCAN-MISS=98 = genuinely-absent names (test probing readdir-missing entries — expected).
- Residual = `readdir count exp=800 got=799` (off-by-one DOWN) = data-block CREATE-MISS / data-block lost-update (a node's create not visible/durable on the reader's DATA blocks). DIFFERENT bug from the leaf-hash hole. Also the round-1 got=700 (one full node's entries missing).

### NEXT: the dir_reuse residual is now the DATA-block create-miss (readdir count drift, both up=phantom and down=lost). The leaf-hash hole (lookup_fail) is HEALED on read. Note: removename for node format still -ENOENT on a leaf-hash hole (no datascan fallback there) → could still leave a +1 phantom; consider a datascan-based removename heal if phantom drift persists. See [[sess22-FINAL-keeper-DFDBAAFE-and-remaining-deep-bugs]] [[sess22-8tcp-full-suite-landscape-13of17-noshutdown]].

---
name: sess23-SMOKINGGUN-freeindex-not-epoch-stamped-node-format
description: sess23(ccloop) SMOKING GUN: xfs_dir2_node.c (node-format FREEINDEX block, xfs_dir2_free) has ZERO b_mxfs_dir_epoch/gen/incarn stamps — the ONE dir bl…
metadata:
  type: project
---

## sess23 (ccloop) — SMOKING GUN for the 8-node dir_reuse clobber

### Confirmed (grep, no run needed)
`b_mxfs_dir_epoch =` stamp sites exist ONLY in: xfs_da_btree.c (read-time), xfs_dir2_data.c (data blocks), xfs_dir2_leaf.c (leaf blocks). **xfs_dir2_node.c has NONE** — the node-format FREEINDEX block (xfs_dir2_free, modified via xfs_dir2_free_log_bests @370/476/1210/2000/2068 and xfs_dir3_free_log_header @391/477/1238/1789) is NEVER stamped with the dir coherency epoch/gen/incarn at modify, unlike data and leaf blocks.

### Why this lines up with the 8-node-specific failure
- leaf→node format transition ≈ blocksize/8 ≈ 512 entries (4K blocks).
- 4 nodes = 400 entries = LEAF (no freeindex block) → dir_reuse PASSES (4/4 verified).
- 8 nodes = 800 entries = NODE (freeindex block exists, and it's the un-stamped block) → FAILS.
The freeindex (bests[] = per-data-block free-space summary) drives addname's data-block + slot selection (xfs_dir2_node_addname_int, xfs_dir2_node.c ~1907). A stale freeindex across a cross-node handoff → addname targets a data-block slot a peer already filled → overwrites the peer's dirent → durable clobber.

### Fix candidates (next session, RULE 4 — instrument first)
1. PROVE: instrument xfs_dir2_node_addname_int to log the freeindex bests[] vs the freshly-read data block's actual free space at the chosen findex/offset. Free-block-said-free but data-block-occupied = confirmed stale-freeindex clobber.
2. FIX A: add the modify-time coherency stamps (b_mxfs_dir_epoch = dp->i_dlm_dir_valid_epoch, b_mxfs_dir_gen, b_mxfs_dir_incarn) to the freeindex block at its log sites in xfs_dir2_node.c, mirroring xfs_dir2_data.c:887 / xfs_dir2_leaf.c:409 — so the freeindex participates in the read-time epoch invalidation + write-side guards like the other dir blocks. (NOTE: the read-time stamp at xfs_da_btree.c:3739 already stamps the freeindex on READ, so cross-node read-invalidation MAY already cover it — verify whether the gap is the modify stamp or something else.)
3. FIX B: on a cross-node node-format addname, force a coherent re-read of the freeindex block before slot selection (xfs_dir2_free_read), and re-validate the chosen data-block free slot against the freshly-read data block before xfs_dir2_data_use_free. Re-examine why the sess22 L3 guard fired 0× — it likely validated the data block's own bestfree, not the freeindex.

### Ruled out this session (do not repeat)
Acquire/read-side epoch invalidation (racy/flaky), release-side eager-evict-on-BAST (harmful: leaf corruption), DLM release→grant ordering (inspected sound). Buffer eviction is the wrong lever; this freeindex-coherency angle is NEW and format-localized.

### Keeper
Build EF6000F0 == 18064D1D behaviorally (params default-off). Validated: dg_shadow eviction-immunity (reliable epoch), 1/tcp=16/16, 2/tcp=17/17, 4/tcp dir_reuse=4/4. 8/tcp dir_reuse = lone blocker. See [[sess23-NEXT-hypothesis-node-format-freeblock-coherency]] [[sess23-STATE-keeper-18064D1D-1and2-tcp-pass-8-is-lone-blocker]].

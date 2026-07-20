---
name: sess23-NEXT-hypothesis-node-format-freeblock-coherency
description: sess23(ccloop) HIGH-CONFIDENCE next target: 8-node dir_reuse clobber is NODE-FORMAT freeindex (xfs_dir2_free bests[]) staleness. CONFIRMED via XFS fo…
metadata:
  type: project
---

## sess23 (ccloop) — HIGH-CONFIDENCE next target: node-format freeindex coherency

### The 8-node threshold IS the leaf→node format transition (confirmed by XFS math, no run needed)
XFS dir2 leaf→node transition happens when the leaf hash array exceeds one leaf block ≈ blocksize/8 = 4096/8 ≈ **512 entries**.
- 4 nodes: 4×50×2 = **400 entries → LEAF format** (free space tracked inline in the leaf; NO separate xfs_dir2_free block). dir_reuse 4/tcp PASSES (4/4 verified this session).
- 8 nodes: 8×50×2 = **800 entries → NODE format** (separate xfs_dir2_free freeindex block(s) with bests[] = per-data-block free-space summary). dir_reuse 8/tcp FAILS (flaky durable clobber).
The 8-node failure boundary falls EXACTLY across the leaf→node transition → the clobber is in the NODE-FORMAT-only free-slot path.

### Mechanism
xfs_dir2_node_addname_int (xfs/libxfs/xfs_dir2_node.c ~1907) reads the FREE block (freeindex) to pick a data block with space, then reads/RMWs that data block via xfs_dir3_data_read → xfs_dir2_data_use_free. Across a cross-node handoff the FREE block's bests[] can be STALE (says data block X has a free slot a peer already filled), so addname targets a slot the peer used → overwrites the peer's dirent. A coherent DATA-block re-read alone doesn't fix wrong SLOT SELECTION driven by the stale freeindex. This is the sess22 free-slot double-alloc; the residual cause is FREE-block staleness, not data-block.

### Ruled out this session
- Acquire/read-side prior-tenure invalidation (epoch/gen): racy, flaky.
- Release-side eager-evict-on-BAST (dir_bast_evict): harmful (evicting leaf blocks → leaf-hash corruption, r12 lost 86).
- DLM release→grant ordering: inspected SOUND (release fence drains before unlock-send before next grant; xfs_mxfs_dlm.c ~6981-7027/7840, dlm.c promote_waiters ~1623).

### Next experiment (RULE 4)
1. Instrument xfs_dir2_node_addname_int: log freeindex bests[] value + chosen findex/data-block + chosen offset; after the data-block read, check whether that offset is ACTUALLY free in the coherent data block. Free-block-said-free but data-block-occupied == PROVEN freeindex staleness.
2. Re-examine WHY the sess22 L3 free-slot guard (before xfs_dir2_data_use_free) fired 0× — it likely checked the data block's OWN bestfree, not the cross-block freeindex; the staleness is in the FREEINDEX (xfs_dir2_free), so the guard must re-read/re-validate the freeindex on a cross-node modify.
3. Fix: coherently re-read the xfs_dir2_free freeindex block before slot selection on a cross-node node-format addname (the freeindex is in the data fork; ensure it's FUA-refreshed across handoff — verify it gets epoch-stamped/invalidated like data blocks; it may be the ONE block type that isn't).

### Keeper (carry forward)
Build EF6000F0 == 18064D1D behaviorally (dir_tenure_evict + dir_bast_evict both default-OFF). Validated gain: dg_shadow eviction-immunity → reliable epoch; 1/tcp=16/16, 2/tcp=17/17, 4/tcp dir_reuse=4/4. See [[sess23-STATE-keeper-18064D1D-1and2-tcp-pass-8-is-lone-blocker]] [[sess23-REFUTED-eager-evict-on-bast-harmful]] [[sess23-eviction-immunity-fixes-epoch-but-residual-is-acquire-side-racy]].

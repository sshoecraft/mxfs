---
name: sess20-PROVEN-dabuf-hole-is-stale-leaf-fixed-by-postread-leaf-only
description: sess20(ccloop) PROVEN via P14/P15 probes: dir_reuse low-mht DABUF_MAP_HOLE shutdown = STALE cached LEAF referencing peer-freed data blocks. FIXED by…
metadata:
  type: project
---

## sess20 (ccloop) — DABUF_MAP_HOLE root PROVEN + fixed; deeper layers mapped

### Build `5C08C626` (from F141D09D). Two new changes, BOTH default-off:
- `xfs/libxfs/xfs_da_btree.c`: postread_reread now gated by new `mxfs_dir_postread_leaf_only` (default 1) → when postread is on, only re-read LEAF/NODE ops (`xfs_dir3_leaf1/leafn/da3_node_buf_ops`), not DATA blocks.
- `xfs/xfs_mxfs_dlm.c`: added `int mxfs_dir_postread_leaf_only = 1` + module_param.
- `scripts/qnap_scale.sh`: added `inode_mht_ms=50` to OPTS (ship-criterion only; /dev/sdb absent here so NOT run in suite — harmless).

### PROVEN (RULE 4, P14-DABUF-HOLE + P15-EXTSHAPE probes already in xfs_da_btree.c ~2826):
The catastrophic dir_reuse low-mht shutdown `!(flags & XFS_DABUF_MAP_HOLE_OK)` at xfs_da_btree.c:2876 = a **STALE cached LEAF block** that still references DATA blocks a peer LEGITIMATELY freed. Probe evidence (ino=136 test dir): in-core extent map is FRESH+CONSISTENT (`loaded_gen==dir_gen` at EVERY hole) = `{off0→fsb15, off5→fsb262153, leaf→fsb786441}`, di_size=24576 (6 blocks) with blocks 1-4 as legal HOLES (peer freed empty middle data blocks). The leaf walk (rm/lookup/readdir) asks to map bno=1,2,3,4 → hole → EFSCORRUPTED. The leaf is the ONLY structure mapping name→block, so it's the stale element. CONFIRMED independent of dir_coherent_modify (release_invalidate-only run STILL had DABUF-HOLE 6-60×).

### FIX CONFIRMED: `dir_postread_reread=1` (re-reads stale clean leaf under held lock before it's walked) → DABUF-HOLE count 6-60 → **0**. P67 fired 17-80×. H-READ (stale cache) proven; H-WRITE (disk inconsistent) refuted for the hole.

### BUT postread on DATA blocks TEARS: a hot dir3_data block FUA-re-read reads the PLATTER (write_cache=write-through, but FUA still catches torn/freed-reused state) → Metadata CRC error (magic=0 zeroed header) → new shutdown. So `leaf_only=1` restricts re-read to mapping blocks. With leaf_only: DABUF-HOLE=0, CRC dropped 60→10, shutdown pushed t=80s→430s (round 24).

### DEEPER RESIDUAL (next layer, UNSOLVED): with leaf fixed, the read of dir3_data **daddr 0x70 = fsb 14** fails CRC (zeroed dir3 header). fsb 14 is NOT in the dir's fresh extent map {15,262153,leaf} — so SOMETHING maps a dir logical block to fsb 14 (a freed-and-reused block owned by another structure). This is the **dir-block-shares-daddr / AG double-allocation** family (sess38-47 bnobt). Enabling `dir_modify_extent_reload=1` (did NOT fire, P14-MODEXT-RELOAD=0 — epoch trigger dead per sess14) shifted failure to `ltbno+ltlen>bno` in xfs_free_ag_extent = **AG free-space double-free**. So the deepest root is cross-node dir block alloc/free incoherence.

### NEXT STEP (RULE 4): instrument xfs_dabuf_map SUCCESS path (multinode dir DATA fork) to log bno→bm_bn + nextents, grep for the map that yields bm_bn=112 (daddr 0x70) → see which logical bno maps to fsb 14 and whether the extent map or a stale leaf produced it. See [[sess20-mht-tradeoff-no-single-value-coherency-fix-required]].
</body>
</invoke>

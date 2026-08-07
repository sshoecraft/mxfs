---
name: ccloop-c7ee71c6-sess48-STEP3-layout-blf-bit5-token-after-map
description: sess48 step-3 layout: XFS_BLF_MXFS_AUTHORITY=(1&lt;&lt;5) (bits 5-10 free; 11-15=BLFT); token appended after blf_data_map in the format iovec; offset…
metadata:
  type: project
---

# Step 3 layout decision — blf v2 authority token

## Facts (xfs/libxfs/xfs_log_format.h)
- `struct xfs_buf_log_format`: type/size/flags/len/blkno/map_size/data_map[XFS_BLF_DATAMAP_SIZE].
- blf_flags bit usage: 0-4 = INODE_BUF/CANCEL/U-P-GDQUOT; 11-15 = BLFT type (XFS_BLFT_SHIFT=11); **bits 5-10 FREE**.
- Format emission: pal/linux/xfs_buf_item.c (xfs_buf_item_format/_size, upstream shape: format iovec length = base_size = offsetof(blf_data_map) + map_size*sizeof(int)).

## Decision
- `#define XFS_BLF_MXFS_AUTHORITY (1<<5)` in xfs_log_format.h next to the dquot bits.
- Token struct (new, in xfs_log_format.h, packed/fixed):
```
struct mxfs_blf_authority {
    __be16 mba_version;      /* 1 */
    __be16 mba_class;        /* MXFS_AUTH_CLASS_AG / _SB / _NONE... */
    __be32 mba_resource;     /* agno for AG class */
    __be64 mba_grant_epoch;  /* pag_mxfs_grant_epoch at iop_format */
    __be32 mba_owner_slot;
    __be32 mba_owner_boot;   /* disklock ctx->epoch (node-instance) */
};  /* 24 bytes */
```
- Writer (xfs_buf_item_size + format in pal/linux/xfs_buf_item.c): when multi-node && the buffer classifies (AG-resource by daddr→agno; SB/global its own class), size += 24, set bit 5, append the token bytes immediately after the map words in the SAME format iovec (offset = base_size). Capture at IOP_FORMAT time per the step-2b directive (CIL push context; xfs_perag_get by daddr, read pag_mxfs_grant_epoch; epoch==0 ⇒ emit class=NONE — fail closed at replay).
- Replay (pal/linux/xfs_buf_item_recover.c): if bit 5, token at ri_buf[0].i_addr + recomputed base_size (from blf_map_size — NEVER trust a stored offset); length check; foreign replay applies iff exact match vs the fenced slot's {resource, ex_grant_epoch} (+owner checks); untagged/malformed/epoch-0 ⇒ P223-style skip (later: abort-no-DONE per ruling).
- Log-incompat: gate with an sb/log feature flag so old kernels reject (we control both ends; fresh mkfs per prep makes rollout trivial on the rig).
- Owner_boot source: disklock ctx->epoch (node-instance epoch, memory ...-disklock-record-recon); owner_slot = mxfs_v5_dlm_get_node_slot.

## Order of remaining work
3a: struct + flag + writer (size/format) — passive (nothing reads it) → soak.
3b: replay-side parse + P223-B print (report-only decode on foreign replay) → verify tokens arrive intact via foreign_replay_ab.sh.
4: descriptor + DONE + victim-slot freeze (v5_mount.c:1197/1274 ordering).
5: enforcement gate swap + A/B + 5-point fault injection.

## Standing: 0.11.396 fleet, 13 clean cycles, criteria NO (11 OPEN of 39, 4 critical).

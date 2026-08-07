---
name: ccloop-c7ee71c6-sess48-STEP3a-emission-mechanics
description: sess48 step-3a mechanics: emit token via single-region copy (local blf+token buffer → xlog_format_copy base_size+24); MUST bump size_segment nbytes i…
metadata:
  type: project
---

# Step 3a emission mechanics (pal/linux/xfs_buf_item.c)

## How the format region is emitted today
- `xfs_buf_item_size_segment` (~126): `*nbytes += xfs_buf_log_format_size(blfp)` + per-chunk bytes; feeds the CIL shadow-buffer allocation.
- `xfs_buf_item_format_segment` (~280): `blfp = xlog_format_copy(lfb, XLOG_REG_TYPE_BFORMAT, blfp, base_size)` — copies base_size bytes into the log vector and RETURNS the emitted copy (later `blfp->blf_size++` mutate the emitted region). base_size = xfs_buf_log_format_size = offsetof(blf_data_map) + map_size*4.

## Implementation choice
Single-region append (option b): build a small local buffer = [blf base_size bytes][24-byte mxfs_blf_authority], set XFS_BLF_MXFS_AUTHORITY in its blf_flags, emit ONE xlog_format_copy of base_size+24; keep using the returned pointer for blf_size++ (offsets within the copy unchanged). Do NOT emit a separate iovec region (would shift ri_buf chunk indexing that recovery walks by blf_size).

## HAZARD (silent corruption class)
The size side MUST add the same 24 bytes under the same condition: `xfs_buf_item_size_segment` nbytes += 24 when the item will be tokenized. Size and format run at different times but both under the same bli; make the "will tokenize" predicate a pure function of (mp multi-node && buffer class) so the two always agree — NEVER consult pag epoch in the predicate (epoch==0 still emits a token with class=NONE; presence must be size-stable). Underestimating overruns the CIL shadow buffer.

## Recovery tolerance
Upstream pass2 copies min(ri_buf[0].i_len, sizeof(struct xfs_buf_log_format)) into a local — extra trailing bytes are IGNORED by un-aware readers and readable at base_size (recomputed from blf_map_size) by the new parser. So 3a (write-only) is safe to soak even before 3b's parser exists, and the log-incompat flag can wait for the ENFORCEMENT step (5) — during 3a/3b the token is advisory. (Ruling's fail-closed applies when the gate goes live.)

## Capture at format time (step-2b directive)
In format_segment (CIL push context): bp = bip->bli_buf → daddr → xfs_daddr_to_agno → xfs_perag_get → READ_ONCE(pag->pag_mxfs_grant_epoch) → put. Class: AG for AG-resource buffer types (agmeta ops + inode clusters + dir blocks — everything daddr-in-AG), GLOBAL_SB for sb/log-private (daddr 0 region / sb buf ops), NONE when epoch==0 or unclassifiable. owner_slot = mxfs_v5_dlm_get_node_slot(mp->m_mxfs_dlm); owner_boot = disklock ctx node-instance epoch (plumb a getter if not exposed; see ...-disklock-record-recon memory).

## Multi-map caveat
bli_formats[i] per map segment; token per SEGMENT (each emitted format region carries one) — replay matches per-region daddr→AG anyway. blf_blkno per segment gives the right agno per token.

Everything else: ...-STEP3-layout-blf-bit5-token-after-map (struct/bit/parse), ...-STEP2b-AUDIT-PASS (why format-time capture is sound), ...-STEP2a-SHIPPED (pag epoch source). Criteria: NO — 11 OPEN of 39.

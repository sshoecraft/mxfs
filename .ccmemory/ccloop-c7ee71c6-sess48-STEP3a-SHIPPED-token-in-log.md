---
name: ccloop-c7ee71c6-sess48-STEP3a-SHIPPED-token-in-log
description: sess48 STEP-3a SHIPPED+VERIFIED (0.11.397): authority trailer rides every multi-node buf log record; crash_consistency 204/204 on tokened logs; next…
metadata:
  type: project
---

# Token campaign — step 3a SHIPPED + VERIFIED (0.11.397, srcver CBFBA5D4)

## Shipped
- xfs/libxfs/xfs_log_format.h: `XFS_BLF_MXFS_AUTHORITY (1<<5)`, `MXFS_AUTH_CLASS_{NONE,AG,SB}`, `struct mxfs_blf_authority` (24B packed BE: version/class/resource/grant_epoch/owner_slot/owner_boot), MXFS_BLF_AUTHORITY_V1/SIZE.
- pal/linux/xfs_buf_item.c:
  - file-scope: `struct mxfs_v5_dlm;` fwd + externs (is_single_node, get_node_slot) — m_mxfs_dlm is void* in xfs_mount.h so calls convert fine; the fwd kills scoped-struct warnings.
  - `mxfs_buf_item_wants_authority(bip)` — pure predicate (mp multi-node), used IDENTICALLY by size and format sides.
  - xfs_buf_item_size_segment: `*nbytes += MXFS_BLF_AUTHORITY_SIZE` when predicate (stale never reaches it; ORDERED emits nothing; non-stale total then round_up 512 — reservation still needed pre-round).
  - xfs_buf_item_format_segment: non-stale+predicate branch builds local {blf[base_size], token} and emits ONE region of base_size+24 (separate iovec would shift ri_buf chunk indexing); sets the flag bit only in the emitted copy; blf_size++ mutations on returned pointer preserved. Fill: xfs_sb_buf_ops→SB; agno<agcount→perag_get→READ_ONCE(pag_mxfs_grant_epoch), nonzero→class AG+resource+epoch; else NONE. owner_slot=mxfs_v5_dlm_get_node_slot; owner_boot=0 for now (fill when the descriptor work lands; ruling calls owner fields defensive-optional).
- Recovery untouched: only check on the region is xfs_buf_log_check_iovec (bitmap-bounds, pal/linux/xfs_buf_item_recover.c:192) — longer region passes; token invisible until 3b.

## Verified
prep+reap+matrix 9/9 clean; rsync lap 32/32; sweep zero; **crash_consistency 204/204** (dirty-log replay of tokened records at 32 nodes). 15 clean fossil-arm cycles across 394-397.

## Next: step 3b — replay-side parser (report-only)
In pal/linux/xfs_buf_item_recover.c near the P223 skip (xfs_log_recover.c:2049/2128 does the skip via mxfs_foreign_replay_untagged_apply — the parse likely belongs where the foreign gate inspects items): if blf_flags & XFS_BLF_MXFS_AUTHORITY, token at ri_buf[0].i_addr + base_size (recompute from blf_map_size; bounds-check i_len ≥ base_size+24; version==1). Print P227-TOKEN decode (class/resource/epoch/slot) count-limited on FOREIGN replay only. Verify via tests/foreign_replay_ab.sh that victims' records arrive tokened with sane epochs. THEN step 4 (descriptor+DONE+victim-slot freeze at v5_mount.c:1197/1274) and step 5 (gate swap: exact-match vs fenced slot ex_grant_epoch replaces the P223 untagged skip; class NONE/mismatch → skip; A/B + 5-point fault injection).

## Criteria: NO — 11 OPEN of 39 (4 critical). Fleet 0.11.397 32/caw healthy.

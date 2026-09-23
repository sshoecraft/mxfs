<!-- sess445 RULE-5 ruling D-0512 (dir sf->block re-type voids the authority token): fix = A' pending-witness reclassify at next protected dirty; MIXED on… -->
# sess445 ruling (gpt-5.6-sol) — D-DIR-SF-TO-BLOCK-RETYPE-VOIDS-AUTHORITY-TOKEN-SLICE-REFUSED-0512

## Defect
xfs_dir2_sf_to_block: xfs_dir3_data_init sets DIR_DATA_BUF + logs (capture instant, mba_blft=DIR_DATA), then xfs_dir3_block_init re-types DIR_BLOCK_BUF. Serialize arm (2) (pal/linux/xfs_buf_item.c ~1446: cap->mba_blft != current blft) voids → class NONE / INCOMPLETE → foreign replay refuses the slice (chain 35 pt 13: bootstrap REFUSED on slot 24). Same shape: xfs_dir2_leaf_to_block, xfs_dir2_block_to_leaf, xfs_dir2_node.c:909/924.

## Ruling: A′ (not A as proposed)
- NEVER classify synchronously inside xfs_trans_buf_set_type (header/owner may be uninitialised for the new format).
- On blft change with an existing capture in this txn window: mark AUTH_BLFT_PENDING + record new blft.
- At the NEXT protected dirty/log of that buffer: classify with the current blft + initialised image. VALID and the complete proof identity (class, resource, epoch, lineage, every authority-defining field) equal to the original capture → accept: update only mba_blft. Different authority → MIXED. Cannot prove → INCOMPLETE/UNPROVEN (never keep the old proof as if the transition succeeded). Original mount identity + proof stay immutable (witness validation, not a replacement capture).
- Type change with NO subsequent dirty → stays void (serialize emits NONE/INCOMPLETE); keep the existing final blft compare as backstop. Multiple type changes before the next dirty collapse to the final type.
- Any path that logs the newly-typed buffer before writing a trustworthy owner fails closed → fix by reordering init/log, never by deferring further.
- B (blft-pair whitelist) NOT recommended; C (format-time capture) and D (replay-side acceptance) remain rejected.

## Measurement order
Producer probe (P-AUTHCAP-VOID on a live fleet create burst — chain 38) is sufficient pre-fix evidence; full takeover lap not required. Landing A′ needs: conversion txn serializes VALID with the inode authority; a victim slice holding it foreign-replays; owner/proof change → MIXED refused; type change w/o dirty → INCOMPLETE refused; unparseable transitional header fails closed.

## STOP-SHIP list
classify in set_type; pending cleared without a post-transition dirty classification; serialize consumes old capture while pending; first post-transition dirty before owner init in any path; failure falls back to old proof; compare only class/resource; parser trusts unchecked offsets/asserts on transitional contents; negative MIXED + no-dirty tests absent.

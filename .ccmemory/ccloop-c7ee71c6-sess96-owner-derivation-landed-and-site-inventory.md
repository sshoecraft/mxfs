---
name: ccloop-c7ee71c6-sess96-owner-derivation-landed-and-site-inventory
description: sess96: step 5.3 owner-derivation LANDED (0.11.429, builds clean, not wired) + the complete line-verified inventory of inode grant-state sites the ru…
metadata:
  type: reference
tags: [sess96, step5.3, authority-token, foreign-replay, D-FOREIGN-REPLAY-UNGATED-IMAGES, inventory]
---

# sess96 — owner derivation LANDED (0.11.429) + grant-state site inventory

Build: **0.11.429**, `srcversion 827A127C599DA93C6DDD3DF`, builds clean. Only new warning is
`mxfs_buf_derive_owner defined but not used` — expected, the producer ladder is not wired
yet (the sess96 ruling redesigned what it must be wired TO).
**NOT deployed, NOT rig-verified.** Rig is still prepped at 0.11.427.

## What landed — `pal/linux/xfs_buf_item.c`

`struct mxfs_buf_owner {ino, valid}` + `mxfs_buf_derive_owner(bp, blfp, out)` +
`mxfs_owner_hdr_ok()`. Implements the sess95 ruling's validation ladder exactly:

- derives from `xfs_buf_offset(bp, 0)` (map 0 — correct for discontiguous/vmapped buffers);
  designed to be called ONCE per logical buffer log item, never per segment.
- gated on `xfs_has_crc(mp)` — only v5 headers carry owners.
- families and their exact magic + BLFT conjunctions:
  `xfs_dir3_{data,block,free}_buf_ops` → `xfs_dir3_blk_hdr.owner`;
  `xfs_dir3_{leaf1,leafn}/xfs_da3_node/xfs_attr3_leaf_buf_ops` → `xfs_da3_blkinfo.owner`
  (da3_node legitimately verifies BOTH DA3_NODE and DIR3_LEAFN — both exact pairs accepted);
  `xfs_attr3_rmt_buf_ops` → `rm_owner`; `xfs_symlink_buf_ops` → `sl_owner`;
  `xfs_bmbt_buf_ops` → `bb_u.l.bb_owner`.
- **the bmbt trap the ruling named**: `XFS_BLFT_BTREE_BUF` is shared with every AG btree, so
  BLFT cannot discriminate. `b_ops == xfs_bmbt_buf_ops && magic == XFS_BMAP_CRC_MAGIC` is
  the exact test (BMA3 is only ever a long-format inode-owned block), plus a
  `XFS_BTREE_LBLOCK_CRC_LEN <= blen` check so a short-form block can never be read through
  the long-form union arm.
- every path also checks header-fits, `uuid_equal(..., &mp->m_sb.sb_meta_uuid)`, and
  `xfs_verify_ino()`. Any failure → `valid=false` → OWNER_UNKNOWN. **No AG fallback.**

Header note: all the buf_ops symbols come from `xfs_shared.h` (already included) EXCEPT the
dir3 family, which needs `xfs_dir2.h`. Do NOT include `xfs_attr_remote.h` / `xfs_symlink.h`
/ `xfs_da_btree.h` — they emit incomplete-type warnings here and supply nothing new.

## Line-verified inode grant-state site inventory (`xfs/xfs_mxfs_dlm.c`)

**DISK acquire → EX** (3): `28370`, `28634`, `29418`. All shaped
`if (mode > ip->i_dlm_mode) { ip->i_dlm_mode = mode; if (mode == EX) { churn_check;
i_mxfs_ex_grant_seq = atomic64_inc_return(&mxfs_ex_epoch); i_dlm_ex_acquire_ns; tenure_ops=0; } }`
under `spin_lock(&ip->i_dlm_lock)`. **The ruling says this predicate is NOT a valid
acquisition identity** — needs a per-attempt cookie.

**LOCAL grant → EX, no on-disk slot** (2): `29525` (`grant_local_new`), `29643`
(`rearm_unpublished`). Must NEVER mint a certificate.

**MIRROR re-affirm** (3): `25970` (ioend admit), `27601`, `27904` (P79-NESTADMIT /
-LOOP). Shaped `if (ip->i_dlm_mode < g) ip->i_dlm_mode = g;` — can raise NL→EX with no fresh
acquire. Ruling: never mint here.

**mode = NL** (11): `13626 13639 15192 19248 26318 26388 27404 30891 31143 31924 41332`.
Nine are paired with `i_dlm_epoch++` on the next line (`13628 13641 15194 19250 26320 26390
30893 31145 41334`); **`27404` and `31924` lower the mode WITHOUT bumping**. Per the sess96
ruling these 11 are cleanup, not the invariant — the revoke must hook release-BEGIN.

## CAW-side facts (`dlm/dlm_caw.c`)

`caw_grant_epoch_update()` (line 940) sets `s->ex_grant_epoch = s->generation` on EX/PW only;
callers bump `generation` immediately before. Called at **6** sites: `2989` (main grant CAS),
`3667` (claim into empty slot), `4461` (compat-add), `6109` (convert/upgrade), `7632`/`7660`
(batch lock). Each of the first four is followed by a `caw_grant_meta_store()` on CAS
success (`3009 3882 4483 6117`); the two batch sites store nothing. These 6 are where the
ruled out-parameter must be populated.

`mxfs_dlm_caw_read_ex_grant_epoch()` (1749) does a full `find_slot()` = **at least one disk
read** — that is why the AG path's approach cannot simply be copied to per-inode acquires
(RULE 0), and why the rejected cache proposal existed at all.

`ctx->grant_meta[]`: 32768 direct-mapped buckets, `{resource, dir_epoch, handoff,
dir_block0_*, releasing, grant_seq}`, mutex-protected, exact-resource-match on read.
Keep as a hint; **must not carry certificate provenance**.

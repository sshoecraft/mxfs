---
name: ccloop-c7ee71c6-sess232-finobt481-mechanism-atomic-skip-partial-writeback
description: sess232: #21 finobt-481 MECHANISM = ATOMIC-SKIP abandoned committed victim txns whose buffers were PARTIALLY home (AGI+finobt yes, inobt no); AG5 con…
metadata:
  type: project
---

# sess232 — D-FINOBT-IBT-FREE-MISMATCH-481 mechanism identified

## Mechanism
Foreign-replay ATOMIC-SKIP (P227-FR-ATOMIC-SKIP, the #1 containment) skips any
txn containing an untagged image. Inode log items carry NO authority tokens, so
essentially EVERY real victim txn is skipped (all 29 in incident481 on test13).
Skipping a COMMITTED txn is only safe if none of its buffers were written home
by the victim's AIL before withdrawal. In 481, victims wrote AGI+finobt home but
not inobt, then withdrew → durable tear: finobt fc ahead by the frees,
AGI==finobt, inobt stale, freed inodes resurface as nlink=0 orphans on no bucket.

## Evidence (tests/evidence/incident481-ccwedge/)
- P227-TOKEN blkno decode: AG base daddr = ag*4186440 (agblocks=523305); offset
  2=AGI, 24=inobt root, 32=finobt root, 8=bnobt, 16=cntbt, 1=AGF.
- Skipped AGI+inobt+finobt txns: AG1 slots 1, 26; AG4 slots 28, 29(x2); AG5 slot 5.
- chk: AG1+AG4 damaged (the exact same-shape +4 delta), AG5 clean → AG5 is the
  control: skip alone harmless when writeback was all-or-none.

## Exonerations (code audit)
- xfs_inode_uninit: difree BEFORE iunlink_remove, one txn — txn layer cannot tear.
- mxfs_ifree_unlinked_preflight logs nothing to tp; -ESTALE clean-cancel claim holds.
- pal/linux/xfs_buf_item_recover.c:1062: stock XFS_LSN_CMP, no cross-node
  discriminator (inode side has di_changecount, buffers do NOT) — latent hole,
  currently unreachable because atomic-skip fires first. Must be fixed before/with
  full tokenization (#1) or partial-apply becomes the new tear source.

## Linkage
Root shared with #1 (missing tokenization prevents APPLY) and #6 (recovery
published complete over the tear). #21 verification: repro victim-commits-difree
+ partial AIL home (AGI+finobt not inobt) + withdraw + survivor replay → chk clean.

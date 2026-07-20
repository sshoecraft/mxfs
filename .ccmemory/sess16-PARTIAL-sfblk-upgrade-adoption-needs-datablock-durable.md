---
name: sess16-PARTIAL-sfblk-upgrade-adoption-needs-datablock-durable
description: sess16 PARTIAL FIX result (build 3BE73553, REVERTED): adopting a peer's block-format dinode when in-core is shortform (gen-independent peer-modified…
metadata:
  type: project
---

## sess16 PARTIAL FIX (build 3BE735532FF98E2911F2C5E, deployed+tested, then REVERTED to clean 03A6D084).

## WHAT I TRIED: in mxfs_dlm_reload_inode (~5211), added `disk_dir_block_upgrade`: a FRESH plain-bdev read of the on-disk dinode; if in-core fork is LOCAL (shortform) but fresh-disk di_format is EXTENTS/BTREE, a PEER grew the dir sf->block (gen-INDEPENDENT peer-modified signal, reliable under reuse where peer_modified_since_load false-negatives). Added to mxfs_dir_disk_superset so the node ADOPTS the peer's block dir instead of keeping+rewriting its stale shortform.

## RESULT (cc_blockdir_probe, ino=131 reused):
- IMPROVED: clean iters 1-12 (baseline failed at iter 2); loss shrank 4-100 entries -> 2 entries; onset delayed iter 2 -> 13. So the sf->block oscillation IS a real part of the root and adopting-the-upgrade helps.
- BUT did NOT eliminate, AND introduced corruption: test2 `Metadata corruption detected at xfs_dir3_block_read xfs_dir3_data block 0x1f0` (=daddr 496). P16-SFBLK-UPGRADE fired only 1x (test2), 0x (test1) — engagement was rare/timing-dependent (the disk format OSCILLATES, so when a node reloads the disk is often shortform again).
- Residual clobber still present: test2 P62-RELOAD-FORK-SHRINK incore_fmt=2 disk_fmt=1 shrink=1 (block-in-core adopting a peer's stale shortform-on-disk = the DOWNGRADE side, which I did NOT address).

## ROOT CAUSE of the corruption (KEY INSIGHT): adopting a block-format on-disk DINODE is unsafe when the dir's converted DATA BLOCK is not yet durable on the LUN. The peer converted sf->block in-core and wrote the block-format dinode, but the new data block (daddr 496) was NOT durably written (the exact handoff-durability gap GPT flagged). Adopting the block dinode then reading the not-yet-durable data block => corruption. So the upgrade-adoption MUST be combined with a guarantee that the peer's converted data block is durable before we adopt (or re-read FUA/verify the data block).

## REVERTED because a rare corruption is a worse regression than the single-test failure. Clean baseline restored = 03A6D084 (== 17DCD050 15/16 + instrumentation).

## SYNTHESIS for NEXT (this is the full picture now):
The crash_consistency durable loss = sf<->block FORMAT OSCILLATION under inode reuse, with TWO coupled defects:
1. A node holding stale shortform doesn't reliably adopt a peer's block (gen false-negative) -> rewrites stale shortform (downgrades disk).
2. A node holding block adopts a peer's stale shortform (P62 shrink=1 downgrade) -> reverts its block entries.
BOTH must be fixed, AND the conversion's DATA BLOCK + dinode must be DURABLE together before any handoff/adoption (GPT demote-drain by lock ownership [[sess16-gpt-architecture-demote-drain-by-lock-ownership]]). The right fix is GPT's full architecture: on EX release, drain BOTH the dinode AND all dir data blocks (incl. just-converted) to the LUN atomically-enough that the on-disk dir is always self-consistent (dinode format matches durable data blocks), so a peer adoption is always safe; AND make adoption format-monotonic (adopt upgrades, refuse non-post_release downgrades). The upgrade-adoption alone (this attempt) is necessary but insufficient and unsafe without the data-block durability. [[sess16-FORMAT-DIVERGENCE-shortform-vs-block]] [[sess16-NEXT-FIX-refinement-selfskip-needs-fresh-read]] [[sess16-HEAD-status]]

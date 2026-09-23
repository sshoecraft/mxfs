---
name: trap-xfs-bli-inode-alloc-buf-is-sticky-so-a-later-unlink-on-that-cluster-still-carries-the-allocation-flag
description: TRAP (s99): XFS_BLI_INODE_ALLOC_BUF is never cleared, so an unlink's di_next_unlinked image reads bli_flags=0x5a and any predicate excluding it fires…
metadata:
  type: feedback
tags: [xfs, replay, authority, buf_item, iunlink]
---

# XFS_BLI_INODE_ALLOC_BUF is a sticky lifetime flag, not a statement about the image

## What it cost

`mxfs_buf_iunlink_ag_authorized` (pal/linux/xfs_buf_item.c) — the producer half of
"fix shape B", which classifies a `di_next_unlinked` image under the AG grant —
excluded any buf log item carrying `XFS_BLI_INODE_ALLOC_BUF`, reasoning that the
allocation form would let replay write whole inode cores.

Measured on the 2-node TCP rig: **shape B fired zero times** across a whole
unlink workload (`P-IUNLINK-AGCLASS = 0`), while 14 inode-cluster images went out
unauthorized. A producer probe printed

    P239-DINO-NOAUTH blkno=4332136 len=32 ag=1 ge=1 bli_flags=0x5a
        blf_flags=0x4001 inode_ops=1 comm=unlink

`bli_flags = 0x5a` = `DIRTY|LOGGED|XFS_BLI_INODE_ALLOC_BUF(0x10)|XFS_BLI_INODE_BUF(0x40)`
— the allocation flag set on an **unlink**.

## Why

- `xfs_trans_inode_alloc_buf()` sets it (`xfs/xfs_trans_buf.c:870`) and **nothing
  ever clears it**. `xfs_buf_item_format` clears only `XFS_BLI_INODE_BUF`
  (`pal/linux/xfs_buf_item.c:2175`).
- The `xfs_buf_log_item` is **buffer-scoped**: it survives across transactions and
  relogs, so the flag persists for as long as that cached cluster buffer's bli lives.
- So every later `di_next_unlinked` update to a cluster whose buffer once served an
  allocation still reads as "the allocation form".

The flag carries **buffer-item ordering and lifetime** semantics (unpin / AIL
retention until the newly initialised cluster is on disk). It says nothing about
what recovery will do with a *later* image. Using it as an authority discriminator
is a category error, and a design consult called it that.

## The right discriminator on v5

`xfs_buf_item_format` sets the wire flag `XFS_BLF_INODE_BUF` **unconditionally**
when `xfs_has_v3inodes()` (`pal/linux/xfs_buf_item.c:2170-2176`), so replay always
dispatches to `xlog_recover_do_inode_buffer`, which applies only `di_next_unlinked`.
And an allocating transaction's cluster image is marked **ordered**
(`xfs/libxfs/xfs_ialloc.c:515-523`) and is never physically logged at all — only
`xfs_icreate_log` is. So on v5 the excluded class cannot exist.

Gate such a predicate on `xfs_has_v3inodes()` — the same feature predicate the
formatter uses — not on `xfs_has_crc()`.

## The consequence when it misfires

One unauthorized image ATOMIC-SKIPs the whole committed transaction, the foreign
replay is POLICY-REFUSED (`-117`), and the victim's AG mask is quarantined
cluster-wide needing operator repair. A silently-never-firing authority predicate
therefore presents as "crash recovery of a dead peer does not work".

## Also

`P227-TOKENSUM`'s `dino_none=` / `dino_agsib=` fields already answer "would shape B
have applied here?" — `dino_agsib == dino_none` means every classless inode-cluster
image had its AG sibling in the same transaction. Read that pair before theorising.

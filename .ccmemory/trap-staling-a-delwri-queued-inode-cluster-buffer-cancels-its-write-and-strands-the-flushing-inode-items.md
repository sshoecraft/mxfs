---
name: trap-staling-a-delwri-queued-inode-cluster-buffer-cancels-its-write-and-strands-the-flushing-inode-items
description: TRAP (0.90.24, 4/tcp): xfs_buf_stale on a cluster buffer with _XBF_DELWRI_Q set drops its write; flushed inode items stay FLUSHING in the AIL forever.
metadata:
  type: feedback
tags: [xfs_buf, stale, delwri, ail, inode-cluster, unmount-hang, release-drain]
---

# Staling a queued inode cluster buffer strands its flushed inode items

**What happened (0.90.22 to 0.90.24, 4-node TCP):** the buffer-cache walk at a
fresh AG grant (`mxfs_dlm_invalidate_ag_meta`, `xfs/xfs_mxfs_buf.c`) staled
inode cluster buffers whatever they carried.  `xfs_buf_stale` clears
`_XBF_DELWRI_Q` (upstream contract: a stale buffer is never written), and
`xfs_buf_delwri_submit_prep` drops a listed buffer whose flag is gone without
writing it.  When xfsaild had already flushed inodes into the buffer, no
completion ever ran: the items stayed in the AIL with `XFS_LI_FLUSHING`
(item flags 0x21), and xfsaild passes over flushing items.

**What it cost:** 5 s per contended inode in the release drain
(`P113-DRAIN-WEDGE` twice, then `P136-DRAIN-RESCUE`), and an unmount that
waited 127 s (`P128-AILSTUCK`).  About 1 lap in 8 of
`tests/quiesce_remount_access.sh`.

**The signature in a stuck-item report:** cluster buffer flags `0x40` (stale
alone), `hold` equal to `nli` (only the items hold it), `onlist=0`,
`last_delwri_submit=never`, event ring ending in a STALE with nothing after.

**The rule for any code that stales a cluster buffer by lookup:**
- never stale one with `_XBF_DELWRI_Q` set; decide under the buffer lock,
  which is what the flag is set and cleared under;
- every other lookup-staler uses `mxfs_buf_has_uncheckpointed_mods(bp)`
  (pinned, items attached, buffer log item, or queued) and keeps the buffer;
- a buffer with inode items attached and NOTHING flushed may be staled: the
  flush writes and completes through the same buffer (measured: 16 to 84 such
  stales a lap, none left an item behind).

**Still unguarded, never observed:** the inode reload's verify-retry loop
(`xfs/xfs_mxfs_reload.c`, the `while (fa && t++ < 8)` after
`xfs_dinode_verify`) stales with no check.  It ran in none of 160 node-logs.
Do not patch it from reading: what it should do with a kept buffer depends on
how each of about 20 reload call sites treats an abandoned reload.  The
instrument below names it if it ever fires.

**Instrument kept in the module:** `xfs_buf_stale` prints
`P-STALE-WITH-ITEMS ... delwri= onlist= caller=` when items are attached.
A line with `delwri=1` is this fault, whoever the caller is.

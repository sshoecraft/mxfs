---
name: user-mxfs-gets-its-own-magics-and-old-volumes-are-refused
description: USER 2026-09-26: every XFS-derived on-disk magic is MXFS's own (MXFS_*_MAGIC names + values). Just change it: no legacy define, no old-version messag…
metadata:
  type: user
tags: [on-disk-format, xfs, decision, naming]
---

After a linux-xfs reviewer asked that MXFS "use different magic numbers so that a mxfs image left in the wild is not mistaken for an xfs one", the user decided every XFS-derived magic becomes MXFS-specific: the superblock and its per-AG copies, AGF/AGI/AGFL, all btrees, inodes, dquots, dir/attr/symlink blocks, and the log record and transaction headers. Landed in 0.90.0.

Two corrections from the user while it was being done, both delivered angrily:
- NAMES: they are MXFS magics, so the symbols are MXFS_SB_MAGIC, MXFS_DINODE_MAGIC, MXFS_LOG_HEADER_MAGIC_NUM and so on, never XFS_*_MAGIC with a new value. The same goes for the userspace tools' private copies.
- NO LEGACY: do not add a "legacy" XFSB define, a "last version that reads it" string, or an old-format refusal message citing a previous release. Just change the magic. An old volume fails the ordinary bad-magic check, and that is the whole of the compatibility story.

The magic table is in xfs/libxfs/xfs_format.h, xfs_da_format.h and xfs_log_format.h. tests/mxfs_magic_isolation.sh proves stock xfs_repair, blkid and xfs.ko do not recognise a new volume.

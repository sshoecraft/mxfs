---
name: trap-a-mount-hook-before-xfs-mountfs-cannot-use-the-fsb-to-daddr-macros-because-m-blkbb-log-is-still-zero
description: TRAP (D-0531, s61a): XFS_FSB_TO_DADDR in xfs_fs_fill_super before xfs_mountfs shifts by m_blkbb_log=0 (set in xfs_sb_mount_common INSIDE xfs_mountfs…
metadata:
  type: feedback
tags: [xfs_super, mount, geometry, slice-lifecycle, instrument]
---

# The daddr macros are dead before xfs_mountfs

`pal/linux/xfs_super.c` runs the MXFS envelope parse, `xfs_readsb`, the DLM
init and the heartbeat slot claim BEFORE `xfs_mountfs`.  In this fork
`xfs_sb_mount_common` — which sets `mp->m_blkbb_log = sb_blocklog - BBSHIFT`
and the other derived geometry — is called only from `xfs_mountfs`
(`xfs/xfs_mount.c:869`), so between `xfs_readsb` and `xfs_mountfs`
`m_blkbb_log` is 0 and every macro built on `XFS_FSB_TO_BB` /
`XFS_FSB_TO_DADDR` / `XFS_AGB_TO_DADDR` returns filesystem blocks where it
promises sectors (off by the 8x block/sector ratio).

How it bit (0.88.0 first lap, s61a): the slice lifecycle claim computed the
slice payload as `BBTOB(bt_sector_offset + XFS_FSB_TO_DADDR(sb_logstart) + …)`
and zeroed 66781184 bytes at 3782775296; the slice is at 27071496192
(`tools/slice_image.py geom`: xfs_data_offset 455815168 + (12*541497+5)<<12).
The harness's `P-SLIFE` lines said READY, the control arm passed (its mkfs
zero had landed anyway), and the variant failed identically to the unfixed
build — the plant was never touched, 64 MiB of the data area was.  The
arithmetic `log_phys - x = 8 * (payload_off - x)` solved for x gave the
envelope's data offset exactly, which is what proved the cause.

Rules:
- In any code that runs in `xfs_fs_fill_super` before `xfs_mountfs`, derive
  geometry from `mp->m_sb` fields directly: `agno = fsb >> sb_agblklog`,
  `agbno = fsb & mask`, `bytes = (agno * sb_agblocks + agbno) << sb_blocklog`.
- Print the absolute offset the code acts on (`P-SLIFE-ZEROING payload_off=`)
  and compare it against an independent tool's number in the evidence.  A
  state machine reporting success says nothing about WHERE it acted.
- A harness that asserts only the fix's own log line passes on a fix that
  acted on the wrong bytes; the platter-side assertion (here
  `foreign_at_crash=0`) is the one that carries the verdict.

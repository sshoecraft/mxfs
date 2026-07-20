---
name: feedback_use_mxfs_tools_not_xfs
description: "Use MXFS's own userspace tools (mkfs_mxfs/chk_mxfs/resize_mxfs/caw_verify), never xfs_db/xfs_info/xfs_repair, to inspect or manage an MXFS filesystem."
metadata: 
  node_type: memory
  type: feedback
  originSessionId: 1d07d44f-fe21-4f11-aa6f-00f01b63d982
---

Never use XFS userspace tooling (`xfs_db`, `xfs_info`, `xfs_repair`, `xfs_admin`, etc.) on an MXFS device or mount. MXFS is XFS-on-disk-*compatible* at the kernel level, but its userspace tools live in `/src/mxfs/tools/` and are the correct (and only supported) way to inspect/manage an MXFS FS:

- `tools/mkfs_mxfs <dev>` — format (writes the MXFS envelope: disklock + journal regions, not a plain XFS sb at offset 0).
- `tools/chk_mxfs [-v] <dev>` — fsck/validate; `-v` prints detailed geometry + per-check info (use this for agcount/agblocks/geometry, NOT xfs_info).
- `tools/resize_mxfs` — grow.
- `tools/caw_verify`, `tools/fua_verify` — transport/coherency checks.
- `tools/mxfs_lock`, `tools/mxfs_bench.{c,sh}`, `tools/mxfs_multinode_bench.sh` — DLM + bench.

**Why:** `xfs_db -r -c "sb 0" /dev/sda` and `xfs_info /mnt/shared` return EMPTY/garbage on MXFS — the MXFS on-disk layout has a bt_sector_offset envelope (disklock slot table + journal slice precede the XFS sb region), so xfs_db reads the wrong sectors and xfs_info doesn't recognize the `mxfs` mount type. Reaching for XFS tools wastes cycles and yields no data.

**How to apply:** When you need MXFS geometry (agcount, agblocks, inode span for AG-distribution analysis) or to validate/repair, run `tools/chk_mxfs -v <dev>` on a node. To compute AG from an inode number you still need agblocks*inopblock — get those from `chk_mxfs -v`, not xfs_info. See [[reference_prior_mxfs_versions]] and CLAUDE.md "tools" subsystem.

---
name: reference-mxfs-igrab-call-site-file-id-mapping-for-refev-and-grabst-probes
description: Decoder for the `site=fileN:lineM` form printed by MXFS reference probes: 1=xfs_mxfs_dlm.c 2=xfs_icache.c 3=pal/linux/xfs_iops.c 4=xfs_filestream.c.
metadata:
  type: reference
tags: [reference, instrumentation, igrab, refcount, probes]
---

# Decoding `site=fileN:lineM` in MXFS reference probes

MXFS wraps `igrab()`/`iput()` per translation unit with a numeric file id, so every
reference event carries its call site. `MXFS_REFEV_SITE(file, line)` packs it as
`(file << 32) | line`, and the probes print it as `site=fileN:lineM`.

**The mapping (from the per-file `#define igrab(vi)` lines):**

| id | file |
|---|---|
| 1 | `xfs/xfs_mxfs_dlm.c` |
| 2 | `xfs/xfs_icache.c` |
| 3 | `pal/linux/xfs_iops.c` |
| 4 | `xfs/xfs_filestream.c` |

A reference taken anywhere else (upstream XFS, the VFS) is NOT wrapped and shows as a raw
return address printed with `%pS` instead — `kind < 2` in the ring means exactly that.

## Where the data lives

Per `struct xfs_inode` (`xfs/xfs_inode.h`):

- `i_mxfs_refev_ip/kind/cnt/head` — a 10-entry ring of grab/release events.
  `kind`: 0=rele 1=grab(ip) 2=grab(file:line) 3=rele(file:line).
- `i_mxfs_grabst[16]` / `i_mxfs_grabst_kind[16]` — the OUTSTANDING-grab stack, scoped to
  the current tenure (reset by `mxfs_inode_tenure_reset` from `xfs_fs_drop_inode`, i.e. at
  the `i_count`→0 transition). With `i_count == 1`, slot 1 IS the outstanding reference.
- `i_mxfs_tgrabs` / `i_mxfs_tputs` — running totals; `i_mxfs_grab_file`/`_line` — last grab.

## Consumers

- `xfs/xfs_icache.c` ~375-407 — the unmount leaked-inode probe (`P203-LEVEL`, `P202-REFEV`).
- `xfs/xfs_inode.c` — the D-0941 poison-retirement failure dump (`P566-GRABST`,
  `P566-REFEV`, `P566-GRABST-SUMMARY`), added sess566.

This machinery existed for the unmount-busy-inode work long before anything else consulted
it. If a probe reports a reference count and not a holder, this is the thing to reach for.

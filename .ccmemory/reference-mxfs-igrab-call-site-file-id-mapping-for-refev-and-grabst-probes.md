---
name: reference-mxfs-igrab-call-site-file-id-mapping-for-refev-and-grabst-probes
description: Decode `site=fileN:lineM` / `file:line` sites: 1-4 = xfs_mxfs_dlm.c, xfs_icache.c, xfs_iops.c, xfs_filestream.c; 5-35 = the xfs_mxfs_*.c split (0.89.…
metadata:
  type: reference
tags: [reference, instrumentation, igrab, probes, layout]
---

# Decoding MXFS call-site ids

MXFS wraps `igrab()`/`iput()` per translation unit with a numeric file id, and since
0.89.89 the forensic "where did this happen" fields of the XFS-side DLM layer record
the same id: `MXFS_SITE = (MXFS_TU_ID << 16) | __LINE__`, printed as `file:line`
(`MXFS_SITE_FMT`/`MXFS_SITE_ARGS` in `xfs/xfs_mxfs_dlm.h`). Fields that carry it:
`i_dlm_demoter_line`, `i_dlm_demoter2_line`, `i_dlm_clobber_victim_line`,
`i_dlm_nl_line`, `i_mxfs_auth_line`, `i_mxfs_auth_try_line`, `i_dlm_epoch_src`,
`b_mxfs_done_site`, the DLMTR ring (`P12-DLMTR ... L<file>:<line>`), the DEMEV ring,
and the AG mutex sites (`P-AGMUTEX-WAIT/HOLD`).

**The table** (authoritative copy: `docs/xfs-dlm-layout.md`):

| id | file |
|---|---|
| 1 | `xfs/xfs_mxfs_dlm.c` (the core file; before 0.89.89 the whole 65K-line layer) |
| 2 | `xfs/xfs_icache.c` |
| 3 | `pal/linux/xfs_iops.c` |
| 4 | `xfs/xfs_filestream.c` |
| 5-35 | `xfs/xfs_mxfs_{authority,iget,durable,dir_bmbt,sb,debug,dir_data,dir_evict,dir_modify,fallible,obligation,relbar,bast,noino,reload,dir_sf,ilock,publish,evict,pubob,ag_meta,disk,coherency,ag_lock,open,ag_unlock,buf,join,recovery,mount,iclus}.c` in that order |

A log or evidence file from BEFORE 0.89.89 prints bare line numbers of the single
65,664-line `xfs_mxfs_dlm.c`; those lines no longer exist in the tree.

## Reference-ring data (unchanged)

Per `struct xfs_inode` (`xfs/xfs_inode.h`): `i_mxfs_refev_*` 10-entry ring of
grab/release events (kind 0=rele 1=grab(ip) 2=grab(file:line) 3=rele(file:line));
`i_mxfs_grabst[16]` outstanding-grab stack for the current tenure;
`i_mxfs_tgrabs`/`i_mxfs_tputs` totals; `i_mxfs_grab_file`/`_line` last grab.
Consumers: `xfs/xfs_icache.c` unmount leaked-inode probe (`P203-LEVEL`, `P202-REFEV`),
`xfs/xfs_inode.c` poison-retirement dump (`P566-GRABST`, `P566-REFEV`).
A reference taken outside wrapped files shows as a raw `%pS` return address (kind < 2).

---
name: trap-a-call-site-read-from-the-tree-may-not-be-in-kbuild-check-the-object-list-and-xfs-stubs-before-making-it-a-boundary
description: TRAP (sess606, D-0958): the plan listed FS_IOC_FSSETXATTR and the ACL read as acquire sites; neither is compiled (Kbuild excludes pal/linux/xfs_ioctl…
metadata:
  type: feedback
tags: [kbuild, stubs, D-0958, audit, xattr]
---

# A call site that exists in the tree may not exist in the module

## What happened (sess606, D-0958)
- The D-0958 plan, written from reading the tree, listed as remaining non-fallible sites: (c) FS_IOC_FSSETXATTR (`xfs_ioctl.c`'s `xfs_trans_alloc_ichange` caller) and, under (a), "the ACL read the VFS issues inside permission checks" (`xfs_get_acl` -> `xfs_attr_get`).
- I wired (c): made `xfs_fileattr_get` and the ioctl's allocator fallible in `pal/linux/xfs_ioctl.c`, wrote a driver op, a flags reader and harness arms. `make` then reported nothing to do and mxfs.ko's timestamp did not move.
- `Kbuild` does not list `xfs_ioctl.o` at all; `xfs/xfs_stubs.c:98` defines `xfs_fileattr_get`/`_set` returning -EOPNOTSUPP and `xfs_file_ioctl` handles only GOINGDOWN and the MXFS private ioctls. `xfs_acl.o` ("needs CONFIG_XFS_POSIX_ACL") and `xfs_handle.o` are excluded too. So there is no FS_IOC_FSSETXATTR, no ACL read on a permission check, and no handle ioctl on MXFS.
- The 0.84.19 CHANGELOG/doc text had already claimed the ACL caller; corrected in 0.84.20.

## The check, before naming any site a boundary or a caller
1. `grep -n '<basename>\.o' Kbuild` — is the file in the object list?
2. `grep -n '<symbol>' xfs/xfs_stubs.c` — is the symbol a stub?
3. `nm mxfs.ko | grep <symbol>` after a build — does the module carry it?
A grep of `*.c` alone finds the tree, not the build; `xfs_stubs.c` is where excluded features answer.

## What is excluded (Kbuild comments, 2026-09-12)
quota, realtime, zones, DAX/pNFS, compat ioctl, dahash test, fsmap, `pal/linux/xfs_acl.o`, `pal/linux/xfs_sysctl.o`, and `pal/linux/xfs_ioctl.c` is simply absent from the list.

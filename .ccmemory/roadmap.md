---
name: roadmap
description: MXFS production-readiness roadmap from the 2026-03-10 session-34 audit (historical).
metadata:
  type: project
---

# MXFS Production Readiness Roadmap

Created: 2026-03-10 (Session 34 audit)
Updated: 2026-03-10 (Session 34 — all items complete except final pre-release)
Target: Proxmox team evaluation submission

## Status: ALL IMPLEMENTATION COMPLETE

Everything from Tier 1, 2, and 3 was implemented in Session 34.

### Completed (Session 34)
1. Bug 109: B+tree extent write + multi-level (v1.8.0 → v1.8.1)
2. Bug 115: mknod — device nodes, FIFOs, sockets (v1.8.2)
3. Bug 116: Long symlinks — FMT_EXTENTS read/write (v1.8.3)
4. Bug 110: xattrs — user/trusted/security namespaces, shortform
5. Bug 111: POSIX ACLs — get/set/inherit, SB_POSIXACL
6. Bug 114: POSIX file locks — fcntl/flock, local-node semantics
7. Bug 113: fallocate — prealloc + KEEP_SIZE + PUNCH_HOLE
8. Bug 112: mmap — page_mkwrite with DLM EX lock
9. SEEK_HOLE/SEEK_DATA — extent map walk
10. Mount options — noatime/relatime/nodiratime/strictatime
11. Splice I/O — filemap_splice_read + iter_file_splice_write
12. Rename flags — RENAME_NOREPLACE + RENAME_EXCHANGE
13. Freeze/thaw — sync + journal checkpoint
14. FINOBT in mkfs — finobt root per AG, resize_mxfs updated
15. Log cleanup — 67 chatty INFO → DEBUG
16. Man pages — mkfs.mxfs.8, chk_mxfs.8, resize_mxfs.8, mxfs.5
17. chk_mxfs improvements — BNO/CNT/inobt/finobt btree walk, inode spot-check, cross-checks

### Remaining — pre-release only
18. Version renumbering: relabel history as 0.x alpha/beta, stamp 1.0.0 on release
19. Final test pass on Proxmox cluster (VM create, VM failover, multi-node stress)

## Post-v1.0.0 (future)
- Quotas (very large)
- Online resize (large)
- Cluster-aware POSIX file locks (large)
- FreeBSD port (large)
- GitHub Actions CI (medium)
- Leaf/node xattr format for large attrs (medium)

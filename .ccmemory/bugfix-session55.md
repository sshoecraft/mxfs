---
name: Session 55 — Bug 131 fix failed, found 19 unchecked writes
description: Bug 131 fix didn't hold (no membership change occurred), found 19 unchecked block_cache_write calls in alloc.c as likely root cause of double block allocation
type: project
---

Bug 131 fix (release cached AG on membership change) was NOT the root cause — corruption recurred after 17 minutes with ZERO membership changes. The dlm_membership_cb never fired.

**Root cause identified**: 19 calls to mxfs_block_cache_write in alloc.c don't check return values. If any fails (iSCSI timeout, cache pressure), the btree modification is silently lost — blocks appear free in bnobt/cntbt while the inode holds an extent pointing to them. Next allocation from that AG hands out the same blocks → file data overwrites inode chunk headers.

**Why:** XFS wraps btree modification + inode extent update in a single atomic journal transaction. MXFS has no such atomicity — these are separate, non-atomic operations.

**How to apply:** Fix all 19 unchecked block_cache_write calls in alloc.c. Full audit at /tmp/unchecked_writes_audit.md. Critical lines: 1645, 1759, 1849, 1935, 2169, 2039, 3493.

Also: alloc.h has guard_map fields added but not yet implemented in alloc.c.

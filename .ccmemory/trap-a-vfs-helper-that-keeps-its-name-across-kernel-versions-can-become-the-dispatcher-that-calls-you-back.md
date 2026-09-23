---
name: trap-a-vfs-helper-that-keeps-its-name-across-kernel-versions-can-become-the-dispatcher-that-calls-you-back
description: TRAP (s140a/s141): inode_update_time(inode, flags) on 6.x is the VFS dispatcher into ->update_time; on 7.x the same name is the helper that returns I…
metadata:
  type: feedback
tags: [lazytime, backport, kernel-version, recursion, panic, vfs]
---

# A VFS helper that keeps its name across kernel versions can become the dispatcher that calls you back

**What bit us (s140a, 2026-09-22).** The corrected lazytime lap's subject arm never returned; test1's serial capture showed a stack guard page hit in `dd` with `xfs_vn_update_time` / `inode_update_time` alternating 169 times, then a fatal exception (panic_on_oops rebooted the guest). The fork's lazytime branch in `pal/linux/xfs_iops.c` did `dirty = inode_update_time(inode, flags)` under the pre-7.0 signature.

**Why.** Upstream 7.x renamed the timestamp-setting helper: `inode_update_time(inode, type, flags)` sets the stamps and returns the positive I_DIRTY_* flags (fs/inode.c). On every 6.x kernel `inode_update_time(inode, flags)` is the dispatcher: `if (inode->i_op->update_time) return inode->i_op->update_time(inode, flags); generic_update_time(...)`. XFS installs `->update_time`, so calling it from inside `xfs_vn_update_time` is calling yourself. The pre-7.0 helpers with the 7.x contract are `generic_update_time()` (marks dirty itself, returns S_* mask) and `inode_update_timestamps()` (S_* mask of what changed, caller marks dirty).

**The second fault the panic hid.** The 0.89.60 `dirty_inode` completion hook used the pre-5.12 guard `flags != I_DIRTY_SYNC || !(i_state & I_DIRTY_TIME)`. Since 5.12 `__mark_inode_dirty` clears I_DIRTY_TIME from `i_state` and passes it in `flags` ("Inode timestamp update will piggback on this dirtying", fs/fs-writeback.c — still present in 7.1), so the callback sees `flags == I_DIRTY_SYNC|I_DIRTY_TIME` and an i_state without the bit; that guard is false on every call and the hook was inert.

**The rule.** When a fork built against a newer kernel is compiled for an older one, a function that compiles under both names is NOT the same function: check its body in the older tree's fs/*.c (or, when only headers are available, its declaration's parameter list and the surrounding comment) before calling it under the `#else` arm. The compiler cannot warn: the older signature accepted the call. Only a live lap found it — and the first thing the lap found was the panic, not the durability question it was built to ask.

**Fix shape that worked (0.89.63):** under the pre-7.0 signature take upstream 6.8's own branch verbatim — `if (!((flags & S_VERSION) && inode_maybe_inc_iversion(inode, false))) { generic_update_time(inode, flags); return 0; }` then log with XFS_ILOG_CORE — and the guard `flags != (I_DIRTY_SYNC | I_DIRTY_TIME)`. Verified: tests/lazytime_timestamp_durability.sh s141a PASS on 06AC7CB42624D7E279F66AF.

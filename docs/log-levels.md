# MXFS Log Level Policy

## Trailing newline — the kernel PAL appends it (0.59.3, sess452)

`mxfs_pal_log()` formats may omit the trailing `\n`; the kernel PAL
(`pal/linux/kern.c`) appends one when it is missing, exactly as the
user-mode PAL (`pal/linux/user.c`) always did.  Until 0.59.3 the kernel
side printed `"mxfs: %pV"` verbatim, and a printk whose text does not end
in a newline is stored `LOG_CONT` with its ringbuffer record committed but
**not finalized** (`kernel/printk/printk.c` `vprintk_store`: `prb_commit`
vs `prb_final_commit`).  `dmesg`, `/dev/kmsg` and journald cannot read an
unfinalized record; it becomes visible only when the *next* printk on the
system reserves a record.  Every PAL marker that ended a quiet period —
the last line of a departure, of a fence, of a settlement — was therefore
invisible to a `umount; sleep 1; dmesg` capture and read as "absent" by
the harness (ledger D-0518: chain 71's crash-model arms all reported the
crash knob "vacuous" while the peers' behaviour proved it had fired).
`xfs_alert`/`xfs_warn` were never affected (`xfs_printk_level` appends the
newline itself).  Do not "fix" individual formats by adding `\n` at call
sites; the chokepoint handles it and a double newline would split the
record.

## Overview

MXFS uses four log levels via `mxfs_pal_log()`:
- `MXFS_LOG_ERR` — errors, I/O failures, critical conditions
- `MXFS_LOG_WARN` — warnings (e.g., pinned block invalidation)
- `MXFS_LOG_INFO` — lifecycle events, membership changes, format transitions
- `MXFS_LOG_DEBUG` — per-operation tracing (compiled out in production)

In the kernel PAL, `MXFS_LOG_DEBUG` maps to `pr_debug()`, which is a no-op
unless dynamic debugging is enabled for the module. This eliminates all
per-I/O log overhead in production.

## What Stays at INFO

These are operational/lifecycle events that fire at most once per mount,
per peer event, or per rare structural change:

- **Mount/unmount**: cache created/destroyed messages with stats
- **Peer events**: node join/leave/ACTIVE transitions, membership changes
- **DLM lifecycle**: created, destroyed, epoch advanced, locks released on unmount
- **Node death**: "purging all locks for dead node N", "purged N locks"
- **Membership changes**: cache invalidation counts, woken pending requests
- **Format transitions**: FMT_EXTENTS -> FMT_BTREE, shortform -> block, block -> leaf

## What Was Demoted to DEBUG

These per-operation messages were causing dmesg spam (hundreds/thousands
per second during active I/O):

### alloc.c (10 messages demoted)
- Per-block allocation: "allocated %u blocks at fsblock"
- Per-inode allocation: "allocated ino %llu from AG"
- Per-block free: "freed %u blocks at AG"
- Per-inode free: "freed inode %llu"
- Inode chunk allocation details
- B+tree leaf compaction/split details (bnobt, cntbt)

### extent.c (1 message demoted)
- Per-inode-flush: "serialized %d extents to btree"

### dir_cache.c (17 messages demoted)
- Per-directory-load: "parsed block dir", "parsed leaf/node dir"
- Per-extent debug: "load ino ... extent[%d]"
- Load path selection: "block path", "leaf/node path"
- Per-flush details: "flush_leaf writing data block", "node format for ino",
  "wrote node format for ino", "flushed dir ino as %s format"
- Cache staleness: epoch mismatch, lock_gen mismatch, EX eviction
- BAST retry/invalidation messages
- DLM shutdown skip messages
- Format verification detail (VERIFY ino)

### inode_cache.c (15 messages demoted)
- Per-ino-128 debug traces: flush/load state dumps
- Per-lock-upgrade: "lock upgrade ino %llu %u->%u"
- Per-epoch-mismatch: re-acquiring lock messages
- BAST handling: deferred, pending, yield, complete deferred
- DLM_TRACE messages: APPLIED_PENDING_BAST, bast_cb ENTRY/DEFERRED/
  INLINE_COMPLETE, inode_cache_put traces, NOT_IN_CACHE handling

### dlm.c (24 messages demoted)
- All DLM_TRACE messages (ino-128 per-lock debugging):
  - BAST FIRE, promote_waiters GRANTED/BLOCKED
  - dlm_lock ENTRY/LOCAL already-granted/new-grant/add-to-waiters
  - dlm_unlock ENOENT/REMOVING/promote_waiters
  - process_remote_request ENTRY/EXISTING/CONFLICT/COMPAT_RESULT/
    GRANT_IMMEDIATE/QUEUED_WAITING/BAST_TARGETS
  - process_remote_release ENTRY/FOUND/ENOENT
- Per-lock retries: transport error, membership change
- Per-resource stale purge details

### block_cache.c (0 messages changed)
All INFO messages were already lifecycle/event level (created, destroyed,
membership change). No changes needed.

## Enabling Debug Output

In a running kernel with dynamic debug:

```bash
# Enable all MXFS debug messages
echo 'module mxfs +p' > /sys/kernel/debug/dynamic_debug/control

# Enable only DLM trace messages
echo 'module mxfs format "DLM_TRACE*" +p' > /sys/kernel/debug/dynamic_debug/control

# Enable only alloc debug
echo 'module mxfs format "alloc:*" +p' > /sys/kernel/debug/dynamic_debug/control

# Disable all MXFS debug messages
echo 'module mxfs -p' > /sys/kernel/debug/dynamic_debug/control
```

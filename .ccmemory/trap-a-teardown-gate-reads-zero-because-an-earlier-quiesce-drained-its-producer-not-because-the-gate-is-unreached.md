---
name: trap-a-teardown-gate-reads-zero-because-an-earlier-quiesce-drained-its-producer-not-because-the-gate-is-unreached
description: TRAP (s109): the post-detach metadata gate counted zero because put_super's own pre-detach xfs_log_quiesce had already emptied the AIL — staging a di…
metadata:
  type: feedback
tags: [measurement-integrity, teardown, authority-gate, vacuous-probe]
---

# A teardown gate's zero is usually its producer, and the producer is usually a quiesce you did not look for

## What happened

The metadata arm of the authority gate is reached only by a metadata write
issued after `put_super` detaches the DLM. Two laps counted zero and the
conclusion drawn each time was about the *gate*: first "the ordering is never
reached", then "MXFS skips the one metadata buffer that tail would submit".

Both were wrong, and the second was backwards. `pal/linux/xfs_super.c:1824`
runs `xfs_log_quiesce(mp)` **only when the SB summary lock was granted**
(`lk == 0`). That quiesce pushes the AIL to empty, and only then does
`put_super` seal the mount and detach at `:2430`. The post-detach
`xfs_unmountfs_finish` → `xfs_unmount_flush_inodes` → `xfs_ail_push_all_sync`
(`xfs/xfs_mount.c:1499`) then finds nothing to write.

So a **refused** SB lock leaves MORE dirty at the detach, not less — the
opposite of what the evidence was read to say.

## Why the obvious staging does not help

"Dirty the filesystem before the umount" cannot populate this arm: the
pre-detach quiesce drains exactly what you staged. Any injection placed
*before* the quiesce is invisible to a gate that sits *after* it.

## The shape of the cure

The producer has to be created **after** the quiesce and after the seal.
In this tree that already existed — `dbg_sb_late_dirty` (the sess475
late-dirty invariant arm, `xfs_super.c:1885-1905`) logs the root inode core
after the seal, so its inode item is still in the AIL at the detach, nothing
before the detach can push it, and the post-detach AIL push submits its
cluster buffer with `m_mxfs_dlm` already NULL.

## The general rule

Before concluding anything from a zero on a teardown path, find every
quiesce, drain and flush between the workload and the gate, and ask which
of them empties the producer. A gate placed after a drain measures only
what was created after that drain. And check the tree for an injection that
already produces it: this one had been sitting in the source for 30-odd
versions under another record's name.

---
name: ccloop-c7ee71c6-sess31-audit-gpt-cond3-satisfied-by-iflushing-interlock
description: AUDIT: GPT condition 3 (per-I/O stage capture) already holds — flush_seq only written under the IFLUSHING interlock, single-flight per inode, iodone…
metadata:
  type: project
---

# sess31 audit — GPT condition 3 (per-I/O tuple capture) already satisfied

`xfs_iflush_finish` promotes `durable_seq = flush_seq` from the inode's CURRENT
field (xfs_inode_item.c:1107), which GPT flagged as a submit→iodone relog race.
Audited: the race is structurally prevented today.

- `i_mxfs_pub_flush_seq` is stamped ONLY in xfs_iflush's success path, which
  runs only after XFS_IFLUSHING was set for THIS flush (xfs_iflush_cluster
  gather sets it at xfs_inode.c:7811; skips inodes already IFLUSHING at
  7755/7777).
- While IFLUSHING is set (from flush through buffer flight to iodone), no
  second xfs_iflush can run for the inode ⇒ flush_seq is STABLE across the
  flight window ⇒ the iodone promotion reads exactly the submitted image's
  watermark. One inode maps to one home cluster buffer, so no cross-buffer
  aliasing.
- ISTALE attach (xfs_inode.c:4849) sets IFLUSHING with NO stamp: its later
  finish re-promotes durable to the OLD flush value — idempotent, harmless.

FRAGILITY (write this into the mask implementation as a comment/assert):
any future path that stamps flush_seq without holding the IFLUSHING interlock,
or that lets two buffers carry the same inode's image concurrently, silently
reintroduces the race. When implementing the stale-stage mask, add
`ASSERT(xfs_iflags_test(ip, XFS_IFLUSHING))` next to the stamp, and keep the
promotion at the existing single point.

Remaining GPT conditions to implement (see
ccloop-c7ee71c6-sess31-GPT-ruling-stale-stage-mask-conditions): 1,2,4,5,6,7,8,9
— start with the default-OFF knob + case-1 skip + P56-style bookkeeping mirror,
then the epoch-validity gate (condition 4 also covers class Z mid-EX submits).

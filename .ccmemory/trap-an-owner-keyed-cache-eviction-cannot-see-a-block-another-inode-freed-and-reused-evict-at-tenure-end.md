---
name: trap-an-owner-keyed-cache-eviction-cannot-see-a-block-another-inode-freed-and-reused-evict-at-tenure-end
description: TRAP (D-0975, 0.87.6): reload-time bmbt eviction keyed on bb_owner==this inode misses a peer-deleted file's cached leaves at addresses the new file's…
metadata:
  type: feedback
tags: [bmbt, buffer-cache, coherency, reuse, tenure, eviction]
---

# An owner-keyed eviction cannot see a block that another inode freed and reused

## What bit
The reload at a re-acquire evicts cached bmbt buffers whose `bb_owner` is the acquired inode. A block freed from inode Y's tree by a peer and reallocated into inode X's tree still carries owner Y in this node's cache, so X's reload cannot find it, and X's first lookup at that address is a cache hit (XBF_DONE, no read) on Y's old leaf. Measured 2/tcp (probe `P975-BMBT-LOOKUP-BAD`): `daddr=120 cached_owner=131 disk_owner=132 same_image=0`, refused by the btree owner check, one write EFSCORRUPTED. The same image under a matching owner (inode number reused, tree at the same address) would have been served silently.

## Why it is structural
Every bmbt image a node caches was read under a grant on its owner, and a block of that tree can only be freed under an EX grant, which needs this node's grant released first. So the image can only go stale after the tenure that read it ended — and that is the moment to retire it, not the next acquire of some other inode.

## The rule (Astra ruling, sess44)
"No reusable XBF_DONE bmbt image from a completed tenure survives that tenure's release." Implemented as `mxfs_bmbt_tenure_end_evict` in the release pipeline before the wire unlock (EX and PR, files and directories, data and attr forks) and in `mxfs_dlm_evict`. Fail-closed: a buffer that cannot be locked in the budget or still carries local work wedges the release. Owner-mismatch re-reads at the consumption point are a detector, not the mechanism: they cannot see the same-owner case.

## Reproduction shape
Two back-to-back 20000-extent laps on one mount, no re-prep between: the first ends with `rm`, the second's new file reuses the freed bmbt addresses (`tests/dio_write_conversion_deadlock.sh NOCAT=1 EXTEND=1 EXTSPAN=1048576 PREFILL=20000`, twice). The harness only removes the file on PASS, so a first lap that fails (e.g. the zero-write rule) silently destroys the precondition for the second.

## Still open
Buffers that log recovery leaves in the cache were read under no tenure (D-BUFFERS-THAT-LOG-RECOVERY-OF-A-DEAD-PEER-S).

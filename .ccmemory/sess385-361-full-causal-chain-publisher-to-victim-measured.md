---
name: sess385-361-full-causal-chain-publisher-to-victim-measured
description: sess385: #361 chain closed end-to-end on ONE incident — test17 published AG4 head 0x82275 with disk_nlink=1; 3.2s later test24 died on that exact ino…
metadata:
  type: project
tags: [agi, unlinked, defect-361, proven, root-cause, dlm-release]
---

## The incident (32/caw, build 86580ED23708F236FB1E5FD, `publish_inodes=0` control arm)

`rsync_paired` FAILED: `nodes_pass=0/32 states:BUDGET_EXHAUSTED=7,FAIL=25`,
10 nodes shut down. Both sides of the handoff were instrumented.

**Publisher — test17, t=9024.891 and t=9025.014:**

    mxfs: P86-AGI-UNLINKED-PUBLISH ag=4 bucket=29 agino=0x82275 ino=17310325
          disk_nlink=1 disk_next=0xffffffff core_nlink=-1 disk_gen=1605863539
          disk_mode=0x81a4

test17 released AG 4 with unlinked bucket 29 pointing at agino `0x82275`, whose
home dinode on the shared LUN read **nlink=1**.

**Victim — test24, t=9028.212 (3.2 s later):**

    XFS (dm-1): Found unrecovered unlinked inode 0x82275 in AG 0x4.  Initiating recovery.
    mxfs: P217-RENAME-FAILSITE site=droplink_tgt rc=-117 ino=17310429 comm=rsync
    mxfs: P217-RENAME-DIRTYCANCEL rc=-117 src=".file5.htpqoe" tgt="file5" comm=rsync
    XFS (dm-1): Corruption of in-memory data (0x8) detected at xfs_trans_cancel+0x15e
                (xfs/xfs_trans.c:1088).  Shutting down filesystem.

**Same AG (4). Same agino (0x82275). 3.2 seconds apart.** rc=-117 = EFSCORRUPTED.

That is the complete causal chain, measured on both sides, from the release-side
split publication to the acquirer's forced shutdown — and then to the
`mxfs_dlm_noino_bast_work_fn` cascade (#474A) that took 10 nodes down.

The acquirer is not corrupt and the AGI is not corrupt. The transition was
published in halves.

## Aggregate for this arm
98 P86 census events, 167 published heads, **3 SPLIT + 4 BADHEAD = 7 bad (4.2%)**.
(An earlier lap measured 11 of 65 = 17%; the rate tracks workload.)

## IMPORTANT — `core_nlink=-1` means "not in THIS node's inode cache"

The killer head above had `core_nlink=-1`. Two readings, and they change what the
fix must cover:

1. The publisher had already reclaimed the inode, so `xfs_iflush_cluster` has
   nothing to convert (no `iip` on the cluster buffer's `b_li_list`) — the
   conversion stage cannot help that case.
2. **More likely: the publisher did not CREATE this head.** P86 audits the AGI
   state at release regardless of who produced it. A node that merely re-publishes
   an AGI it read from the medium will report a bad head that another node left
   there. The fix must make the CREATING node publish jointly; once it does,
   later re-publishers should see `joint_ok`.

So a residue of bad heads in the fixed arm does NOT automatically mean the
conversion stage failed — attribute by whether the reporting node ever had the
inode in core. Do not conflate SPLIT (core_nlink==0, we know it is unlinked) with
BADHEAD (core_nlink==-1, we never had it).

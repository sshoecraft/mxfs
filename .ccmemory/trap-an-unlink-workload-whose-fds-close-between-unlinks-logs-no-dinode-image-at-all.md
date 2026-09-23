---
name: trap-an-unlink-workload-whose-fds-close-between-unlinks-logs-no-dinode-image-at-all
description: TRAP (s113/s114): a replay-guard injector read fired=0 because an unlink-while-open workload that closes each fd before the next unlink never logs di…
metadata:
  type: feedback
tags: [iunlink, replay, fault-injection, harness, xfs]
---

# An empty AGI bucket logs no dinode, so an "unlink while open" workload can produce zero inode-cluster images

## What happened

`tests/tcp_death_replay.sh`'s two durable-write injection arms (`TDR_VICTIM_AGINO`,
`TDR_VICTIM_STRADDLE`) substitute into a **logged** inode-buffer image to exercise
`xlog_recover_do_inode_buffer`'s guards. Both aborted at `stage=victim-inject` with
`fired=0 declined=0`, on a build where the injector code was correct.

The workload was, per file:

    exec 9<$IDIR/u$i && rm -f $IDIR/u$i && exec 9<&-

16 files, each fd closed before the next file is touched.

## The mechanism

`xfs_iunlink_insert_inode` (xfs/libxfs/xfs_inode_util.c) only logs the inode's
`di_next_unlinked` when the AGI bucket it lands in is **non-empty** — it has to be
pointed at the old head. With an empty bucket the on-disk value is already NULLAGINO
and only the AGI buffer is logged. The tree states this itself at :693:
*"with an EMPTY bucket (head == NULLAGINO) ... upstream's empty-bucket path logged no
dinode"*.

Closing the fd immediately frees the inode (`xfs_inactive` → `xfs_ifree` → remove from
the list), so the list was empty again before the next unlink. Every insert saw an
empty bucket. **No `XFS_BLFT_DINO_BUF` image was ever formatted**, so there was nothing
for either injector to land on.

## How to build a workload that actually logs one

- **Hold every fd open across all the unlinks**, and keep holding them past the point
  the image must survive to. That is the whole fix; the count is secondary.
- Closing them afterwards is not neutral: the resulting `ifree`s can stale the cluster
  and emit a CANCEL record, and replay then skips the very image that was injected —
  a vacuous lap that looks like a working one. If the image must survive a VM kill,
  the holder has to outlive the ssh command (detach it), not just the loop.
- Bucket arithmetic: `xfs_iunlink_pick_bucket` is `agino % 64` — consecutive aginos land
  in *consecutive* buckets, so N < 65 freshly-created files collide in none of them.
  But MXFS defaults `mxfs_iunlink_slot_buckets = 1`, which funnels every inode on a
  clustered mount into `m_mxfs_node_slot % 64` — one bucket. So on a clustered mount two
  simultaneously-unlinked-but-open inodes chain; on a single-node mount you need ≥ 65.
  Do not rely on one of those two regimes without checking the knob.

## The measurement lesson underneath it

`fired=0 declined=0` was unreadable: "never called" and "called and rejected every
image" need opposite fixes and looked identical. Both injectors shared a **silent**
first return on `!(blf_flags & XFS_BLF_INODE_BUF)`, while the file's own contract three
lines above claimed an arming that finds no inode-buffer image "stays armed and says
so". Making every rejection path name itself (rate-limited) answered it in one lap:
30 declines, every one a real image, none of them BLFT 8.

Decode these by hand — BLFT is `blf_flags >> 11`, and `XFS_BLF_INODE_BUF` is bit 0.
Observed `0x3820`→7, `0x2020`→4, `0x7820`→15, `0x9020`→18, none of them 8.

---
name: caw-v065-acq-epoch-fix
description: v0.6.5 build CD7D3E62: i_dlm_dir_acq_epoch (advances ONLY at reload adopt fall-through) closes P65 gate defeat; 13/13 green 4/caw cache_coherency
metadata:
  type: project
---

# v0.6.5 acq_epoch fix — uv dangling-dirent closure (sess5 ccloop 186320ae)

## Fix (build CD7D3E624E4FDDD7E86AF79, deployed test1-4)
New `ip->i_dlm_dir_acq_epoch` (xfs_inode.h, after i_dlm_dir_valid_epoch):
- P65 epoch-consume gate (xfs_mxfs_dlm.c ~13655) on CAW now compares
  `dir_grant_epoch != i_dlm_dir_acq_epoch` (TCP unchanged: valid_epoch, >).
- acq_epoch advances ONLY at the reload coherence point (~15245, right before
  the guaranteed xfs_inode_from_disk — no bail between). Keep-stale-guard
  early returns (P43-FMTREVERT-SKIP etc.) leave it lagging → gate re-fires
  next acquire (true level-trigger).
- Init 0 alongside valid_epoch init (~19999).

## Why valid_epoch could not serve the gate
Modify/evict-path hooks legitimately sync valid_epoch UP to master epoch
mid-tenure for buffer stamping + prior-tenure evicts (xfs_mxfs_dlm.c 5318/5342
+ libxfs read hooks xfs_da_btree.c:3575, xfs_dir2_leaf.c:1156,
xfs_dir2_node.c:2090, xfs_dir2_data.c:2224). That erased the acquire gate's
lag with NO adopt having run → a stale dir-block base survived handoffs;
the storm's last unlinks converted block→sf FROM the stale base and durably
re-asserted peer-removed names (uv dangling dirent, IGET-FAIL -2).

## Instrumentation fix (same build)
P136-DIRINO-WRDONE (pal/linux/xfs_buf.c ~1584) was SKIPPING LOCAL(sf)-format
dir dinodes — the sess4 forensics hole ("nobody wrote sf" was an artifact).
Now logs ALL dir dinode images with fmt= gen= added.

## Verification
13/13 consecutive PASS `MXFS_DEV=/dev/mapper/mpatha MXFS_EXTRA_MODARGS="dirwr=1
dirland=1" ./run.sh 4 caw precond_readiness cache_coherency` (prior fail rate
1-in-2..5). P65-EPOCH-ADOPT fires with acq_epoch (347/iter on test1, adopt=1
clean=1, multi-epoch skips like grant=55 acq=53 caught). 0 P106-STALE-EX,
0 P43-FMTREVERT-SKIP during all 13 iters (test4's 6 STALE-EX in dmesg are
pre-session relics, realns ~35min before iter1).

## Next
posix_multi 3/4 at 4/caw, then full 17/17, then 8/16/32 ladder.
[[caw-uv-single-dirent-leak-hunt]] [[caw-v064-prebump-epochconsume-fixes]]

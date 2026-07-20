---
name: sess61-PROVEN-ROOT-stale-shortform-reconversion-clobbers-disk-block-dir
description: sess61 PROVEN ROOT (RULE4, direct evidence): dir_reuse 4-node node1_f* durable loss = a node with STALE in-core SHORTFORM dir re-converts sf->block,…
metadata:
  type: project
---

## sess61 PROVEN ROOT — dir_reuse_coherency 4-node durable node1_f* loss

Build 55885EED. Criterion: 1/2/4/8 tcp 100%. 4/tcp still FAILs dir_reuse_coherency.

### What was REFUTED this session (RULE 4, direct evidence)
- **Logical-block-0 SPLIT (sess42) REFUTED at 4 nodes**: P60-LBMAP shows ALL
  nodes resolve dir logical-0 -> the SAME daddr (e.g. 120 / 33491656), same
  i_gen, same nextents. Extent maps AGREE. Not a physical split.
- **Read-side stale-serve REFUTED**: at verify (PR mode), P61-BLK0 shows block0
  core_node1 == disk_node1 (e.g. 76==76). The data block is coherent at read
  time. P34-TRYLOCK-STALE/DIR-STALE-SKIP/P60-GENMATCH-STALE all ~0 on read path.
  The sess60 readdir gen-bump keeps the PR/readdir path coherent.

### PROVEN ROOT (decisive P61-BLK0 + P42-SFCONV + P60-SFCONV-BASE, test4 r15)
A node holding a **STALE in-core SHORTFORM** view of the shared reused dir
**re-converts shortform->block (xfs_dir2_sf_to_block)**, allocating/overwriting
block0 with ONLY its own entries, durably clobbering all peer entries already
on disk. Decisive trace:
```
P42-SFCONV ino=131 sf_count=11 dlm_mode=5 i_gen=4039824203 addname="node4_f12"
P60-SFCONV-BASE ino=131 sf_count=11 node1f_cnt=0 has_node1_f1=0  (rank4 SF = its 11 own entries, NONE of node1's)
P61-BLK0 ino=131 daddr=6279744 core_node1=0 disk_node1=68 fua_rc=0 dlm_mode=5 comm=dd  (disk already block-fmt w/ 68 node1 entries!)
```
So rank4 thinks the dir is shortform (its own 11 entries) while disk is long
since BLOCK format with 68+ entries (peers converted+grew). Its sf->block
conversion erases the disk block dir => node1_f1..f50 durably lost on ALL nodes.
The proven write-side stale-base RMW = at the FORK-FORMAT level, not data-block.

### WHY the inode fork stays stale (the architectural constraint — in code)
xfs_dir2.c:287-340 (sess56/57/58 comments) + P58-FMT-DISIZE-CORRUPT:
**The MODIFY paths (create/remove/rename via `mxfs_dlm_dir_modify_refresh`,
xfs_mxfs_dlm.c ~2852) only evict cached dir DATA blocks; they do NOT reload the
inode fork (format/di_size/extent map) because `mxfs_dlm_reload_inode` does
`down_write(i_lock)` which SELF-DEADLOCKS under the held ILOCK_EXCL.** So a
modify reaches xfs_dir2_format / xfs_dir2_sf_to_block with a stale fork. Two
failure faces from the same gap: (1) stale BLOCK->LEAF map -> di_size!=blksize
EFSCORRUPTED shutdown (sess57); (2) stale SHORTFORM -> re-conversion clobber
(THIS session's proven node1_f* loss).

### NEXT (fix direction)
Need a lock-held-safe inode-fork reload usable on the modify path (caller holds
ILOCK_EXCL): a `reload_locked` variant that re-reads the dinode + rebuilds the
data fork WITHOUT re-taking i_lock. Trigger it when modify-refresh (or the top
of xfs_dir2_sf_to_block) detects disk di_format/di_gen indicates a peer already
converted/grew this SAME incarnation past our in-core shortform. Safe in the
sf-stale case: we have no own un-checkpointed dir mods yet (conversion is the
first modify), so adopting disk loses nothing. mxfs_dir_force_evict=1 already
(data-block evict runs every modify) but can't help — the staleness is the FORK.

Repro: `./run.sh 4 tcp dir_reuse_coherency` (fails r4/6/9/12 etc). Per-failure
dmesg snapshot now written by the test to /root/drc_fail_r${round}_rank${R}.dmesg
(sess61 added). P61-BLK0 probe (xfs_da_btree.c after the block read) +
console-loglevel note: pr_warn(4) doesn't hit console at default loglevel 4.
See [[sess60-residual-writer-side-durable-node1f1-clobber]],
[[sess57-dir2format-disize-corruption-modify-gap]],
[[sess42-SYNTHESIS-block0-split-is-double-sf-conversion-lineage]].</body>

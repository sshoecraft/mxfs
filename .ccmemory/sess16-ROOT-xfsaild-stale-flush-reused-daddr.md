---
name: sess16-ROOT-xfsaild-stale-flush-reused-daddr
description: sess16 ROOT PROVEN (P35E-DIRWR names trace): crash_consistency clobber = test1 xfsaild flushes a BACKLOG of stale shrinking rm-rf dir-block images on…
metadata:
  type: project
---

## sess16 ROOT (RULE 4, PROVEN via P35E-DIRWR + dirent-NAMES dump, build BFFA37B1, instr=0 dirwr=1).

## Two things established this session:
1. **Read-side discard fix REFUTED** (build 7187ED60): tightening the in-AIL keep-guard to evict `buf_gen < i_dlm_dir_gen` (stale_tenure) caused `xfs_dir3_leaf_read_verify` Metadata CRC corruption + whole-dir 0/200. Because `in_ail+undestaged+buf_gen=0` is AMBIGUOUS: it is EITHER a stale leftover OR a FRESHLY-CREATED current block (data/leaf/free/node) whose content is only in-core+log (disk = garbage). Discarding the latter = corruption. buf_gen is only stamped at read + (my) data-init; leaf/free/node fresh blocks have buf_gen=0. So the keep-guard MUST keep them. **Do NOT re-try read-side discard of in-AIL undestaged dir buffers.** All 3 edits reverted; baseline restored = 01CC6214 (= 17DCD050 logic + lseq/wseq on DIR-STALE-SKIP).

2. **TRUE clobber vector = xfsaild stale-flush onto a reused daddr** (the vector sess15 flagged but couldn't prove). Probe lost node2_f46-f50.md5 (test2's). dmesg P35E-DIRWR for the lost block's daddr=8372976: a tight ~130ms burst of ~30 writes ALL `comm=xfsaild/sda` on TEST1, content a SLIDING/SHRINKING window — nent 15→…→1, names [node2_f22.md5…] sliding to [node2_f50.md5]. = test1's `rm -rf $D` of a PRIOR iter removing node2_f*.md5 one-by-one (removename relogs the dir block each time; xfsaild pushes each shrink state). The CURRENT iter REUSES daddr 8372976 for its new dir; test1's lingering AIL backlog of stale shrinking images is flushed by xfsaild OVER the current dir's fresh content → durable loss (gone from LUN, invisible even to writer test2). It is a LOCAL (single-node test1) bug exposed by daddr REUSE — matches [[sess15-PIVOTAL-loss-requires-inode-daddr-reuse]] (reuse required; cc_minrepro/cc_nogap_noreuse 40/40 clean).

## NEXT (RULE 4): the freed dir block's pending AIL buffer items must be CANCELLED when the block is freed+reused so xfsaild can't flush stale content. Upstream XFS: freeing a metadata block → xfs_trans_binval marks BLI XFS_BLI_STALE → commit cancels it (removed from AIL, write suppressed) AND log-recovery cancel record. CHECK whether mxfs's dir2 shrink/xfs_da_shrink_inode/xfs_dir2 remove path binvals the data+leaf blocks, and whether mxfs's in-AIL keep / drain pipeline RE-INSERTS or fails to cancel them. Likely fix: ensure xfs_trans_binval on dir-block free (or on daddr realloc, xfs_buf_stale the prior buffer). Verify: cc_blockdir_probe clean >25 iters, then FULL ./run.sh 2 tcp 16/16 ×3. Fallback 17DCD050 (15/16).

## INSTRUMENT ADDED (build BFFA37B1, KEEP for now): P35E-DIRWR (pal/linux/xfs_buf.c ~2239) now dumps nent + dirent names[] for XDB3/XDD3 writes (added #include xfs_dir2_priv.h). DIR-STALE-SKIP (xfs_da_btree.c) now prints lseq/wseq/undest. ENV NOTE: test2 mxfs went rmmod-busy (refcnt=1 leaked ref) on redeploy → recovered via `virsh -c qemu:///system destroy test2 && start test2` (boots in ~10s); ALWAYS verify BOTH nodes' srcversion after a redeploy (prep_node silently keeps the old module if rmmod fails). [[sess16-stale-tenure-keepguard-fix]] [[sess15-HEAD-status]]

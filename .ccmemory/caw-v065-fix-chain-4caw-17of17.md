---
name: caw-v065-fix-chain-4caw-17of17
description: v0.6.5 build 656E89B4: FIVE fixes → 4/caw 17/17 ALL PASS. acq_epoch, P106-BAIL, P5R self-trans refresh, destage tenure-refuse+merge, block-format-for…
metadata:
  type: project
---

# v0.6.5 fix chain — 4/caw 17/17 (sess5 ccloop 186320ae, build 656E89B4)

## The five fixes (in order, each RULE-4 proven from dlm_fairness/cache_coherency forensics)
1. **acq_epoch** (`i_dlm_dir_acq_epoch`, xfs_inode.h): P65 CAW adopt gate compares
   grant_epoch vs acq_epoch (NOT valid_epoch, which modify-path hooks up-sync).
   Advances ONLY at reload fall-through (~15245). → cache_coherency 13/13+.
2. **P106-STALE-EX-BAIL** (mxfs_dlm_ilock_begin ~17700): phantom cached-EX serve
   (on-disk slot not ours) now demotes to NL + `goto restart` slow re-acquire.
   Gates: !unpublished, pin==0, state==CACHED, no demoter, <3 laps.
3. **P5R-TRANSREFRESH** (xfs_da_btree.c honor hook ~3280): stale_pending dir block
   joined to OUR OWN clean trans (trylock can never win) → in-place FUA refresh
   under the trans lock (magic+CRC verified). Mid-trans yield → peer modify →
   re-acquire flagged-block case.
4. **P-ICD-TENURE-REFUSE** (mxfs_inode_cluster_durable ~4290): destage-time slot
   verify (every 32nd lap); refuse cluster write from dead tenure. PLUS sticky
   `i_dlm_icd_refused` honored by the reload sf-merge gate
   (`!xfs_inode_clean || icd_refused`) so a ghost-retired-clean inode MERGES
   instead of wholesale-adopting (which reverted committed renames). Cleared
   only at the real-write success exit.
5. **Block-format-for-life** (xfs_dir2_sf.c block_to_sf suppress, multinode +
   force_block) + **xfs_dir_block_isempty** (xfs_dir2.c, tp-aware, used at
   rmdir + rename-target checks): shared dirs never re-enter shortform, killing
   the sf ghost machinery entirely. Empty-block-dir rmdir works via
   xfs_dir3_block_read + xfs_dir2_block_sfsize count==0.
   (precond "unlink/cleanup" FAIL on all nodes was the block-isempty gap.)

## Diagnosis chain (why each was needed — ghosts kept re-minting)
fairness storm = create+mv+rm per round, 4 nodes, one dir. Ghost families:
n2_r15 mv-ENOENT (adopt-empty after mid-mv yield), n4_r10.done / n2_r1 /
n3_r1+n2_r1 ghosts (stale-tenure destage clobber at .6060 inside test3's
gen-27 tenure; refused-destage then flipped to merge-resurrect via clean
adopt; block→sf conversion from stale block crystallized ghosts).
P136 cap was 1200 (3/4 nodes blind 40s before window) → raised to 60000 +
fmt/gen fields + LOCAL dinodes no longer skipped (was EXTENTS/BTREE-only!).

## Key traps for future sessions
- P142 slot dump: hex/self are node-BIT masks (t1=0x1 t2=0x2 t3=0x4 t4=0x8).
- EXREL/EXGRANT rapid cadence (rel_gen +2..4 per 10ms) is NORMAL under storm.
- run.sh FAIL artifacts: /tmp/run_<test>_<RUNID>; PASS runs keep nothing.
- SCST mxfs device: fileio /home/steve/disk.img o_direct=1 async=1 wt=0 —
  ack-after-AIO-complete (read-pass-write NOT proven; the .6238 stale read in
  the n2_r15 case was actually explained by P136 blindness).

## State
4/caw: ALL 17 PASS on 656E89B4 (chunked sequential runs, same build).
Next: ladder 1/2 re-validate on this build, then 8/16/32 (task #5), then
final full ladder + marker (task #6).
[[caw-v065-acq-epoch-fix]] [[caw-uv-single-dirent-leak-hunt]]

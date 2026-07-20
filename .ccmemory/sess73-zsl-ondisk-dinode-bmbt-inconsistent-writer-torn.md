---
name: sess73-zsl-ondisk-dinode-bmbt-inconsistent-writer-torn
description: sess73 (run14d): zsl root = ON-DISK dinode di_nextents < on-disk bmbt-leaf records (CODE-PROVEN via P70 FUA-reread still failing). Writer torn releas…
metadata:
  type: project
---

## sess73 (ccloop 14d31183) — zsl decisively re-rooted: ON-DISK (dinode,bmbt) inconsistency. Marker NOT written.

Build started/loaded: **64932978** (= 55379AA2 sess70 source + P73 diagnostic). All 16 nodes.
zsl still FAILs: `total_fs_silent=1600 completed=1/1` (no shutdown, no eviction this run).

### Two failure faces of the SAME hot-shared-dir bug (ino=131 = /mnt/shared/wa_iter1)
1. **Verify-HANG (uninstrumented 55379AA2, first clean 1-iter run):** the verify `find` wedges D-state forever on ino=131 i_lock. PROVEN it is a **LOCAL leaked i_lock reference**, NOT cross-node:
   - sysrq-w: find(readdir) in `xfs_ilock+0xe0`→**down_write** (ILOCK_EXCL: `xfs_ilock_data_map_shared` upgrades to EXCL to read BTREE extents); 2 find(getattr) in `xfs_ilock+0x18d`→down_read. Queued writer + queued readers, **NO owner thread** (full thread inventory = idle kthreads + xfsaild + the 3 victim finds only).
   - Unmounting the apparent EX holder (test12) did NOT free it → not a cross-node CAW orphan. No "no longer responding"/shutdown/PR-conflict. = sess132's documented leaked-ILOCK (leak SITE still unplugged; release-fence loops 3314-3391/3542-3565 and reload 5004-5193 audited i_lock-BALANCED).
   - Added **P73-ILOCK-STUCK** detector (xfs/xfs_inode.c): xfs_ilock ILOCK acquire now trylock+cond_resched spin; after 5s dumps `rd_held cnt wr_last/pid/comm rd_last/pid/comm un_last` naming the leaker. **Did NOT fire** this run (find hit corruption instead of wedging — the cond_resched spin perturbs the wedge). NOTE: P73 spin changes ilock fairness (RULE 0 timing) — next session may revert to repro the pure wedge, or keep to catch the leaker if it recurs.

2. **DATA-LOSS (instrumented 64932978):** `ls /mnt/shared/wa_iter1` → **"Structure needs cleaning" (EFSCORRUPTED)**, dir_count=0 from test1/5/9 even after sync+drop_caches (links=1207 so entries WERE created). dmesg: `corrupt dinode 131 (btree extents)` at `xfs_iread_bmbt_block+0x450`, repeating, **NO FS shutdown** (EFSCORRUPTED returned per-op).

### CODE-PROVEN ROOT (RULE 4) — on-disk dinode and bmbt-leaf disagree
- Corrupt buffer (72B) decodes as a **structurally VALID** long-format bmbt leaf: magic `BMA3`, bb_level=0, **bb_numrecs=0x13=19**, leftsib/rightsib=NULL, self bb_blkno=0x015e5ad8=22960856. So it's the OVER-COUNT check `ir->loaded + num_recs(19) > ifp->if_nextents` (xfs_bmap.c:1308), in-core dinode stale-LOW.
- The **P70-DINO-RECONCILE** block (xfs_bmap.c:1274-1307) runs UNCONDITIONALLY (only its pr_warn is instr-gated): FUA cache-bypass re-reads THIS inode's on-disk dinode, adopts `disk_nx` iff `disk_nx >= ir->loaded+num_recs`. **Corruption at 1308 STILL fired ⇒ the FUA-fresh ON-DISK dinode di_nextents was ALSO too low.** ⇒ the on-disk (dinode.di_nextents, bmbt-leaf records) pair is **genuinely inconsistent on disk**.
- Therefore: NOT reader cache-staleness. **All read-side fixes (sess68 P68 leaf-refresh, sess70 P70 dino-reconcile) cannot help.** This is a **WRITER-side torn release** of the (dinode, bmbt) pair = sess60's proven finding ([[sess60-zsl-writer-releases-inconsistent-dinode-bmbt]]). Likely mechanism (sess34): a node with a STALE-LOW cached dinode does a mkdir and its release-drain iflush writes the stale-low di_nextents to disk, REVERTING a peer's grow, while the peer's bmbt leaf (19 recs) stays → dinode behind leaves. `P61-CHOKEPOINT-SKIP-BMBT owner=131 daddr=22960856 numrecs=19 NL-released dir, skipping stale leaf write` also fired (a guard, not the fix).

### REFUTES sess70: P70 did NOT eliminate "corrupt dinode" — it recurs. sess70's "PR-preempt→shutdown" is NOT the current cause: the `reservation conflict` lines are BENIGN join-time disklock slot-claim races (t=62, `P130-CLAIM-RACE slot N → claimed slot 5`), one per joiner, not storm writes, no shutdown.

### NEXT SESSION (clear RULE-4 path)
- Root is writer-side. Instrument the dir DLM RELEASE / dinode iflush path to catch di_nextents REGRESSION on disk (a release writing di_nextents LOWER than current on-disk, or lower than the inode's own bmbt leaf sum). Candidate: in the dir release fence (xfs_mxfs_dlm.c ~3314) or the iflush dinode-pack, FUA-read on-disk di_nextents before writing and REFUSE to write a lower value (the peer's grow must win). 
- Verify on-disk vs leaf directly: read dinode 131 + walk bmbt from /dev/sda (or run dirwr=1 once and grep P70-DINO-RECONCILE / P59-IREAD-MISMATCH for loaded vs if_nextents vs disk_nx).
- Other ship-gate FAILs unchanged: fence_during_write lost=400, rsync_paired 148%, posix_semantics_multi16 >600s (same hot-dir family).

Links: [[sess60-zsl-writer-releases-inconsistent-dinode-bmbt]] [[sess59-zsl-residual-bmbt-leaf-disk-staleness]] [[sess70-overcount-fix-and-purge-cascade-fix]] [[sess68-host-loopback-deadlock-and-sharpened-p67-probe]] [[sess65-zsl-dlm-handoff-metadata-coherency-root]]

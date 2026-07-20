---
name: sess93_lessons
description: sess93 — bnobt is a RED HERRING (Gemini #2): legit btree math, not revert. Real root = stale inode/BMAP double-free. gen-bump fix landed (C4E65691).
metadata:
  type: project
---

# sess93 (2026-06-05, ccloop run 29df431e)

cache_coherency still FAIL (passed=1 failed=3: rename 40/240, unlink 3/122 +
"2 files remain", cross_write_read 1/6). Marker NOT written.

## THE BIG REFRAME (Gemini consult #2 — decisive, overturns sess44-92)
**The bnobt "durable lost-update" chased for ~10 sessions is a RED HERRING.**
The bnobt buffer is NOT being reverted/clobbered — it is doing **legitimate
forward B-tree math** (alloc carves a free record, then frees re-insert+merge).

Decoded the full P88 chronological trace for one leaf (AG9 daddr=18785888,
SAME bp the whole time, test3 SOLE owner t=84-237, no peer):
- t=84-90.5: allocator carves blocks 9,10,11,12 from free rec [9,7] →
  [10,6]→[11,5]→[12,4]→[13,3]. Normal. disk image lags in-core by one step
  (async writeback / SCST destage lag) → disk_differs=1 is BENIGN here.
- by t=95.8: all blocks consumed, record deleted (disk_nr=1, rec gone).
- t=95.84: a FREE of block 9 inserts [9,1].
- t=107.54: a FREE of blocks 10-15 MERGES with [9,1] → [9,7]. bnobt
  mathematically reconstructed (LSN legitimately climbs 459→670). NOT a revert.

**My P93-REVERT-CLOBBER probe (disk_nr>in_core_nr) was catching the benign
async-writeback lag + legitimate merge-frees, NOT a bug.** P88/P93/P90/P70
"bnobt clobber" family across sess42-92 were all mis-reading legit btree math
as corruption. STOP instrumenting the bnobt/AGF/cntbt for "stale clobber."

## THE REAL ROOT (Gemini): stale inode/BMAP issues a DUPLICATE free
The xfs_alloc.c ltbno+ltlen>bno double-free shutdown happens because an
**inode's in-core BMAP is STALE** and frees blocks it ALREADY freed (the
bnobt correctly shows them free; the second free overlaps → EFSCORRUPTED).
- Gemini Q2: a stale cntbt/AGF would NOT overwrite bnobt — it'd fail
  xfs_alloc_fixup_trees (i==0) and panic differently. So NOT AG-meta.
- A stale INODE/BMAP buffer absolutely WILL cause this: inode reverts to a
  state where it thinks it still owns freed blocks → truncate/unlink frees
  them again → double-free.
- Corroboration ALREADY in dmesg: many `INACT-SKIP-STALE ino=... reason=
  gen-mismatch|disk-free — skipping destructive inactivation to avoid
  double-free` — a guard already detects stale inodes. And the criterion's
  visibility failures (rename/unlink/cross_write_read) are inode/dir cache
  coherency. ONE unifying root: inode-cache staleness across nodes.

## What I changed this session
1. **Build C4E65691 (KEEP, defensively correct):** bump pag_dlm_meta_gen in
   BOTH release_pending reclaim paths (xfs_mxfs_dlm.c ~4685 and ~4741). The
   release worker yields the on-disk CAW (mxfs_v5_dlm_ag_unlock L6577) BEFORE
   clearing release_pending (L6586), so a reclaim in that window adopts a
   grant the cluster already took WITHOUT bumping gen → stale cached AG-meta.
   Bumping is safe+cheap (drain-before-unlock ⇒ clean buffers; in-AIL/pinned
   protected by read hook). VERIFIED it fires (test2 reached pag_gen=2). But
   it does NOT fix the criterion because the dominant failure is inode/BMAP,
   not AG-meta. Gemini #2: "AG metadata generation strategy is fine."
2. P93-REVERT-CLOBBER probe added to pal/linux/xfs_buf.c (~line 1892, inside
   the P88 `if(nr<=2&&level==0)` block, self-contained, FUA-reads disk_nr).
   It's HARMLESS but catches benign merges — consider gating/removing.

## Refutations established (RULE 4, code-reading + probes)
- Mechanism F (read-completion TOCTOU): REFUTED. mxfs_buf_read_fua →
  mxfs_pal_scsi_read_fua_bdev → scsi_execute_cmd(REQ_OP_DRV_IN, 30*HZ, retries=1)
  is SYNCHRONOUS, run under b_sema in xfs_buf_submit; no concurrent txn can
  modify the buffer mid-read (even readahead holds the lock to ioend).
- The clobber "producer": xfsaild → xfs_buf_delwri_submit_nowait →
  xfs_buf_submit (standard AIL writeback) — but it's flushing LEGIT btree math.
- mxfs_v5_dlm_ag_held only checks OUR CAW bit (not exclusivity).

## NEXT SESSION PLAN (pivot to inode/BMAP — Gemini's Probes B+C)
1. Trap the DOUBLE-FREE: in xfs_free_ag_extent (xfs/libxfs/xfs_alloc.c) right
   before the ltbno+ltlen>bno EFSCORRUPTED return, dump_stack + agbno + len +
   the existing free record. Shows WHICH op (truncate/unlink/bmap_del/EFI-EFD
   deferred worker) double-frees.
2. Trap xfs_bmap_del_extent (or __xfs_free_extent): log ip->i_ino + agbno +
   len. Catch the inode shedding the SAME extent twice = stale BMAP cache.
3. Root is likely: peer modifies/reuses an inode; this node's cached inode +
   BMAP extent list is stale (gen-current-but-stale, the recurring theme of
   sess44/48/90); on unlink/truncate it frees already-freed blocks. Fix the
   inode/BMAP invalidation on cross-node inode reuse, NOT the bnobt.
4. The visibility failures (rename/unlink/cwr) share this inode-coherency root.
   cross_visibility PASSes (shortform fixed sess85); the 3 failing subtests all
   involve inode reuse/reload across nodes.

## INFRA (unchanged from sess92, all still valid)
- Clean reboot ALL 4 (sudo virsh -c qemu:///system destroy+start testN) before
  trusting any run — contaminated state → SESS50-STARVE inode-lock timeouts.
  /tmp/.mxfs_pass: cp ~/.mxfs/pass /tmp/.mxfs_pass. Then bash tests/reset4.sh 4
  (auto NFS-remounts /src). Slots t1=0 t2=3 t3=1 t4=2; ~20 AGs.
- cache_coherency: ( ./tests/criteria/cache_coherency.sh --nodes 4 >/tmp/cc.log
  2>&1; echo EXIT=$? >>/tmp/cc.log ) & ; until grep EXIT=. Mount /mnt/shared,
  dev /dev/sda. Detail log path printed in RESULT reason=.
- Build C4E65691 deployed on all 4 nodes at sess93 end.
</body>

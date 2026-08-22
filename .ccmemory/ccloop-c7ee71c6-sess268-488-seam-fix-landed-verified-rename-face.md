---
name: ccloop-c7ee71c6-sess268-488-seam-fix-landed-verified-rename-face
description: sess268: -488 post-roll ILOCK handoff LANDED 0.11.494, scaling_curve 3/3 PASS (truncate face verified); NEW 4th face = xfs_rename preacquire blocks h…
metadata:
  type: project
---

# sess268 — seam fix landed + verified; rename face opens

## Landed (0.11.494 sv 50088D4764A4A5C726417CE, deployed 32/caw)
sess267 GPT-ruled contended-only post-roll ILOCK handoff, exactly per plan:
1. `xfs_trans.h` t_mxfs_ag_want (perag ref, migrates across xfs_trans_dup,
   put in xfs_trans_free).
2. `__xfs_free_extent`: ANY in-defer trylock fail (SAFE or UNSAFE) → set
   want + -EAGAIN (P271-AGWANT); NOTDEFER → old blocking + audit.
   P271-AGPREDROP (drain+block-under-ILOCK) branch REMOVED — it was the
   sess267-proven poison.
3. `mxfs_defer_agwait()` in xfs_mxfs_dlm.c (P271-AGWAIT-SEAM): drain
   retained grants → detach ili_lock_flags==0 inode items BEFORE iunlock
   (li_trans free for third-party ijoin) → ihold → iunlock → blocking
   ag_dlm_lock → immediate unlock (pregrant to cached) → relock
   ascending-ino → ijoin(0) → irele → shutdown check.
4. Seam hook in xfs_defer_finish_noroll inside the has_intents||dfp
   block after the DIRTY re-roll; error → out_shutdown.
5. Preflights: EFI xefi_agwait cap counts only -ETIMEDOUT (fast -EAGAIN
   composes); trylock returns 0 on cached/nested (holders++).
Facts: post-roll t_items only has lock_flags==0 inodes (save_resources
filters), max XFS_DEFER_OPS_NR_INODES=5; save_resources relogs them each
roll so they're clean at the seam. make clean needed (multi-file) AND
`make tools` after (prep FAIL: mkfs_mxfs wiped by clean).

## Verified
scaling_curve 32/caw 3/3 PASS 32/32 (0.11.493 was 0/32, livelock 2/3).
P271-AGWANT fires with relsafe=1 AND 2; AGWAIT-SEAM inodes=1; no P67
loop from truncate face; no stuck dd fleet-wide after runs.

## NEW: fourth face (rsync_paired FAIL 0/32 NO_TERMINAL_RECORD, 60s)
test3/test20/test26: rsync stuck 212s+ in
caw_wait_for_grant ← __mxfs_ag_dlm_lock ← mxfs_trans_preacquire_inode_ags
← xfs_rename.  test26: P12-AGBAST-RX ag=7 holders=0 cached=1 sched=1
page_ms=198s + P67 AG-AIL-STALL agno=7 stuck_ino=29703747 ilocked=1
in_ail=1 → its own blocked rsync's ILOCK poisons ag=7 drain. Same
Coffman shape via the RENAME path (preacquire blocks while ILOCKs held,
or misses an AG). test20 also showed P5N-AG-ORPHAN-NAK disk_held=0
(benign NAK, bit not set). Next: read xfs_rename ordering vs
mxfs_trans_preacquire_inode_ags; RULE-5 before extending the fix.
Specimen left LIVE on the fleet.

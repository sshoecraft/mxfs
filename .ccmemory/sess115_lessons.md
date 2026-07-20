---
name: sess115_lessons
description: sess115 — drain-wedge ROOT = create-path flush leaks IFLUSHING via manual xfs_bwrite on alloc-buflist-trapped shared cluster; fix in 1853FF8F (UNVERI…
metadata:
  type: project
---

# sess115 (ccloop 4eef1f39) — drain-wedge root NAMED + fix landed (build `1853FF8F`, UNVERIFIED)

## Clean-baseline ground truth (build 6B8A19F5, hard-reboot + reset4)
cache_coherency = **2/4**: cross_visibility PASS, rename_visibility PASS (fast ~1.4s — the
sess108 NEWARCH chokepoint fixed the rename stale-cached-EX). FAILING: unlink_visibility (1-31
fails/122) + cross_write_read (4-5 fails/6). Both reduce to ONE root: a freshly-created small
file/dirent in a SHARED shortform dir is not promptly visible to peers. (Note: the cc_run logs
showing rename wedging 250s + node drops were CONTAMINATED-cluster artifacts; clean = rename PASS.)

## PROVEN durability gap (decisive FUA probe, RULE 4)
Added a probe at the P-SFDIR-REVERT site (reload would shrink a shortform dir): force SCSI
READ(16) FUA of the inode cluster, re-parse count. **ino=128 (mount root /mnt/shared, holds
.mxfs_test/.mxfs_results/.mxfs_barriers): incore_cnt=3 disk_cnt=0 fua_cnt=0 di_gen=0/0** → the LUN
GENUINELY has 0 dirents; the root inode CLUSTER was never destaged (di_gen never advanced past
mkfs). A peer's cold reload reads the empty cluster → clobbers its 3-entry in-core view → ENOENT
storm → 119/120 + missing .md5. (Reused inodes 131/132: disk_gen=incore_gen+1, fewer entries =
genuine newer incarnation after rm+realloc — different case.) ROOT: under CAW a peer's cold read
of a parent inode cluster does NOT BAST the owner, so the sess85 release-path flush never fires →
shortform parent never destaged.

## DRAIN-WEDGE root PROVEN (the sess111-114 wedge) — RULE 4 + RULE 5 (Gemini)
The P112-IFLUSH-CALLER probe (gated ino=128) named the IFLUSHING-setter:
`mxfs_inode_cluster_durable ← mxfs_dlm_dir_inode_durable` = **sess13's create-path flush**.
A/B PROVEN on clean cluster:
- WITH create-path flush: unlink 1 fail/122 (durability WORKS) but **P113-DRAIN-WEDGE** (inode
  stuck XFS_IFLUSHING+in_ail, ili_fields=0, shared cluster buf XBF_DONE-only/off-list/LOCKED,
  holder=xfs_inode_item_push, IO never submitted) → mxfs_ail_drain_inode_sync spins forever →
  SESS50-STARVE → SIGKILL@900s. cross_write_read 127s.
- WITHOUT (call removed, build 5BF32150): wedge=0, cwr 127s→4s, BUT unlink regresses 1→30 fails.
⇒ the create-path cluster flush is NECESSARY for durability; the LEAK (not the flush) is the wedge.

Gemini (RULE 5) root: `xfs_bwrite(r_bp)` clears `_XBF_DELWRI_Q` but does NOT `list_del(&bp->b_list)`.
When a freshly-created CHILD inode shares the parent dir's 4KiB inode cluster, mxfs's alloc path
queued the SHARED buffer on `pag_mxfs_alloc_buflist` (`_XBF_DELWRI_Q|_XBF_MXFS_ALLOC_QUEUED`). The
manual bwrite leaves it physically linked on the alloc-buflist with the delwri flag cleared →
inconsistent state orphans siblings' IFLUSHING (no iodone clears it) → wedge. Also: xfsaild can't
flush these (xfs_buf_delwri_queue returns false on already-_XBF_DELWRI_Q) → only drained on AG BAST.

## FIX LANDED (build `1853FF8F`, UNVERIFIED — next session MUST test)
`mxfs_inode_cluster_durable` (xfs/xfs_mxfs_dlm.c ~426): after xfs_iflush_cluster, **never manual
xfs_bwrite**. Instead native delwri: if `r_bp->b_flags & _XBF_DELWRI_Q` (trapped on alloc-buflist)
→ relse + `mxfs_dlm_ag_drain_alloc_buflist(parent's AG)` (calls xfs_buf_delwri_submit, list-aware,
iodone clears IFLUSHING). Else `xfs_buf_delwri_queue`→relse→`xfs_buf_delwri_submit` on a local list.
Create-path call `mxfs_dlm_dir_inode_durable(dp)` RE-ENABLED in xfs_create (xfs/xfs_inode.c ~1449).
Also KEPT: decisive FUA probe in P-SFDIR-REVERT (xfs_mxfs_dlm.c ~3008, logs fua_cnt+gens).

## NEXT SESSION
1. virsh destroy+start ALL 4 (qemu:///system) → `bash tests/reset4.sh 4` → verify srcversion
   1853FF8F on all 4 → dmesg -C → `timeout 1500 tests/criteria/cache_coherency.sh --nodes 4`.
2. Grep dmesg: `P113-DRAIN-WEDGE` (MUST be 0 = leak fixed) and `P-SFDIR-REVERT` fua_cnt
   (ino=128 should stop showing fua_cnt=0 if durability now destages the root cluster).
3. If wedge=0 AND unlink/cwr improve → progress. If unlink still fails on ino=128 fua_cnt=0, the
   durability still isn't reaching the root cluster (the parent's cluster may NOT be on the
   alloc-buflist when no child shares it — then the `else` delwri_queue path must actually submit).
4. RULE5 escalation chain: Gemini already consulted twice on the drain-wedge (sess112 + sess115).
   If 1853FF8F insufficient, next is ask_gpt with the full A/B + fua_cnt evidence. Gemini's deeper
   rec (sess112+115): re-architect the drain OUT of the BAST locus (GFS2 glock-workqueue) and/or
   reconcile the _XBF_DELWRI_Q/_XBF_MXFS_ALLOC_QUEUED collision so xfsaild can flush alloc-buflist
   clusters. unlink_visibility is also SLOW (~249s) independent of the flush — separate chokepoint
   BAST-drain slowness to investigate.

INFRA: clean run REQUIRES full power-cycle (qemu:///system destroy+start), not just reset4. Marker
NOT written — cache_coherency FAILS. Continues [[sess114_lessons]] [[sess112_lessons]].
</body>

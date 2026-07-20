---
name: sess114_lessons
description: sess114 — cache_coherency wedge TRUE ROOT PROVEN+FIXED: reload of mode=0 peer-freed inode leaves torn LOCAL fork (if_data=NULL,if_bytes>0)→xfsaild if…
metadata:
  type: project
---

# sess114 (ccloop 4eef1f39) — cache_coherency wedge TRUE ROOT CAUSE PROVEN + FIX

## sess113 merge_dirs/FUA theory DISPROVEN (RULE 4 step 2a)
Built+deployed `5E2660AC` (merge_dirs early-return under fua_disable=1). `P113-DRAIN-WEDGE
ino=128` STILL occurs. Full thread census on wedged node: NO thread in any FUA/iflush/push
path; only the BAST drain kworker (victim). The buffer lock is genuinely LEAKED, not stalled.

## TRUE ROOT (RULE 4, dmesg oops, build 5E2660AC) — FULLY PROVEN, exact code path
**xfsaild OOPSES (NULL-deref) mid-push and dies holding ino=128's inode-cluster buffer lock.**
dmesg t=77.197..77.203:
```
P112-IFLUSH-CALLER ino=128 set IFLUSHING ... xfsaild   (locks cluster buf, sets IFLUSHING)
P-IRESURRECT ino=131 incore_mode=00 disk_mode=00       (the torn victim, mode=0)
BUG: kernel NULL pointer dereference address=0x0
RIP: memcpy_orig (RSI=0 src NULL, RDX=6 len)
  ? xfs_iflush_fork+0x143   ? xfs_inode_to_disk+0x93
  xfs_iflush_cluster  xfs_inode_item_push  xfsaild
note: xfsaild/sda[1064] exited with irqs disabled
```
xfsaild gone (pid 1064 absent) → cluster buf never written → IFLUSHING stuck → BAST drain
(mxfs_ail_drain_inode_sync) waits forever → SESS50-STARVE → peer EX times out → cache_coherency
SIGKILL@900s. The "leaked lock" of sess112/113 is a SYMPTOM of the xfsaild oops, not the cause.

## EXACT MECHANISM (every step verified in source)
1. xfs_iflush_fork (xfs/libxfs/xfs_inode_fork.c:580) FMT_LOCAL case: if (ili_fields&DDATA &&
   if_bytes>0) memcpy(cp, if_data, if_bytes). ASSERT(if_data!=NULL) is compiled out in prod.
   CRASH needs: format=LOCAL, ili_fields&XFS_ILOG_DDATA, if_bytes>0, if_data==NULL.
2. xfs_idestroy_fork (LOCAL case) does `kfree(if_data); if_data=NULL` but does NOT reset
   if_bytes or if_format. So after destroy: format=LOCAL, if_bytes=6, if_data=NULL.
3. xfs_inode_from_disk (xfs/libxfs/xfs_inode_buf.c:318-320): `i_mode=di_mode; if(!i_mode)
   return 0;` — a mode=0 (peer-FREED) disk inode early-returns SUCCESS WITHOUT calling
   xfs_iformat_data_fork. So the fork is left EXACTLY as idestroy left it (torn). NO
   "from_disk FAILED" log (it returns 0) — confirmed 0 such logs in dmesg.
4. mxfs_dlm_reload_inode (xfs/xfs_mxfs_dlm.c ~2883 idestroy, ~2912 from_disk) reloads a live
   in-core dirty inode (ino=131, a churned shortform dir in test_rename_visibility) to the
   peer's freed mode=0 disk image → torn fork persists past the ILOCK_EXCL release → next
   xfsaild flush (inode still ili_fields=DDATA) crashes.

NOTE: reload holds down_write_trylock(&ip->i_lock)=ILOCK_EXCL; iflush_cluster takes
ILOCK_SHARED nowait → they serialize, so the crash is a flush AFTER reload leaves persistent
torn state, NOT a concurrent flush-during-reload.

## FIX (build PENDING this session)
In mxfs_dlm_reload_inode, after xfs_inode_from_disk success, if the reloaded inode is mode=0
(freed), reset the data fork to canonical-empty (format=EXTENTS, if_data=NULL, if_bytes=0,
if_nextents=0) — same as mxfs_dlm_reset_inode_for_create (xfs_mxfs_dlm.c:3336-3339). Then
xfs_iflush_fork's FMT_EXTENTS case sees if_bytes=0 → no memcpy → no oops. Discarding the
already-peer-freed fork is coherency-correct (peer's free is authoritative; we reloaded its
image). NEXT: build, deploy to all 4, rerun cache_coherency, grep for absence of the oops +
P113-DRAIN-WEDGE. If passes → run full verify_ship.sh.

## If fix insufficient (RULE 5)
Consult Gemini with THIS oops trace. Deeper question may remain: should a node ever reload a
live dirty inode to a peer's mode=0 free image at all (resurrection/lost-update class)? But the
torn-fork crash fix is necessary regardless. Marker NOT written — criterion FAILS until verified.
</body>

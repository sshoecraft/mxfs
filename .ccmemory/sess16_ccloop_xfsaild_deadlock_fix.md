---
name: sess16_ccloop_xfsaild_deadlock_fix
description: sess16(ccloop) — FIXED xfsaild self-deadlock (rename PASS, 2/4, build 9F289917 VERIFIED). Then build 92CE435D adds cross_write_read page-flush (UNTES…
metadata:
  type: project
---

## sess16 (ccloop 4eef1f39) — drain-wedge FIXED + 2 fixes pending test

### Builds
- `1853FF8F` base (sess14/15, 1/4) → `2AC5E54B` AGI-coldread (INERT) → `9F289917` deadlock fix
  (**VERIFIED 2/4**) → `92CE435D` (adds cross_write_read page-flush, **NOT YET TESTED**).

### VERIFIED WIN (build 9F289917): xfsaild self-deadlock FIXED → cross_visibility + rename_visibility PASS
PROVEN kernel stack (test4, ino=25165953 stuck in_ail ~610s, P113-DRAIN-WEDGE):
```
xfsaild → xfs_inode_item_push → xfs_iflush_cluster [HOLDS cluster buf LOCKED]
        → xfs_iunlock(ip,ILOCK_SHARED) → mxfs_dlm_ilock_end → mxfs_dlm_bast_process → msleep ∞
```
ROOT = accounting ASYMMETRY: `xfs_ilock_nowait(XFS_ILOCK_SHARED)` (xfs_inode.c:230) skips MXFS DLM
for ILOCK (IOLOCK-only; atomic ctx), so iflush takes NO DLM holder ref — but `xfs_iunlock`
(xfs_inode.c:314) unconditionally runs `mxfs_dlm_ilock_end` → inline `bast_process` drain that waits
on the very cluster buffer xfsaild holds. FIX: 3× `xfs_iunlock(ip,XFS_ILOCK_SHARED)` in
`xfs_iflush_cluster` (xfs_inode.c ~4111/4119/4127) → raw `up_read(&ip->i_lock)`. RESULT: P113=0 all
nodes, no wedge/shutdown, passed=2 (was 1). KEEP.

### FIX B (build 92CE435D, UNTESTED): cross_write_read empty .md5
`mxfs_dlm_bast_process` reg-file release (xfs_mxfs_dlm.c ~2200) flushed inode CLUSTER but not dirty
DATA PAGES → unsynced 33-byte .md5 sidecar reads EMPTY cross-node. FIX (Gemini): added
`filemap_write_and_wait(vip->i_mapping)` for S_ISREG at the TOP of the reg/dir durable block (before
the cluster-flush loop + early-out). NEXT: build is done (92CE435D); deploy + run cache_coherency,
check cross_write_read .md5 reads correct.

### STILL OPEN: unlink_visibility — CAW bidirectional STARVATION (369s, ~30/121 fail)
SESS50-STARVE both directions on hot shared dir inode (PR-convoy starves EX unlink; EX holder starves
PR verify-read), t=437→837. sess50 `defer_for_waiter` (dlm/dlm_caw.c ~1523) = readers-yield-to-writers
FRESH-acquire only; doesn't force existing cached holders to release, and EX→PR direction uncovered.
Bidirectional naive yield BROKE (all-4 stall + ENOENT).

**Gemini Problem-A design (handoff token via existing `yield_to`+`waiters` masks, NO new on-disk fields):**
1. Poll thread: BAST local cached holder on ANY incompatible waiter (already does — line 2763 fires
   bast_cb for any incompat; verify EX→PR direction actually drains).
2. On BAST-driven release to NL: if `waiters!=0`, set `yield_to |= waiters` (+timeout) — hand the turn
   to starving peers.
3. Fresh acquire (NL) check `yield_to`: if active & we're NOT in it → MUST yield (register waiter)
   even if mode-compatible (stops re-joining the convoy); if we ARE in it → acquire & clear our bit,
   ignore other incompat waiters (breaks symmetric all-4 stall); if 0/expired → existing
   defer_for_waiter. This is the anti-barging/turn-ticket. Implement in mxfs_dlm_caw_lock.

### METHOD: clean power-cycle (virsh destroy/start ALL 4) before EVERY trusted run; bash tests/reset4.sh 4;
verify /sys/module/mxfs/srcversion; `nohup timeout 1100 ./tests/criteria/cache_coherency.sh --nodes 4`;
detail = newest /tmp/cache_coherency.*.log. Marker NOT written — 2/4.

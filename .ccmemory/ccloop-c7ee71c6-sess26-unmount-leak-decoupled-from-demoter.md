---
name: ccloop-c7ee71c6-sess26-unmount-leak-decoupled-from-demoter
description: D-UNMOUNT-BUSY-INODES reproduced on the current build and DECOUPLED from the demoter clobber (P74/P76 both 0). P203-LEVEL attribution is only sound u…
metadata:
  type: project
tags: [unmount-busy-inodes, refcount-leak, xfs_lookup, rule4, refutation, attribution]
---

# sess26 — unmount inode leak: reproduced, and decoupled from the demoter clobber

## Reproduced on the CURRENT build

Build `8E827AAB556A0E21AF739C9` (v0.11.228) — two-slot demoter fix AND the P6
peer-notification fix both active. Documented sequence at 16/caw:

    prep -> inode_reuse_typeflip 15 16 2 8 (PASS typebad=0)
         -> cache_coherency (PASS 16/16 590/590)
         -> sf_mkdir_storm 12 16 2 1 (PASS)
         -> unmount_leak_check 16

Result: **leak=1 on test10** (1 of 16, matching the documented rate), with the
VFS slab warning:

    kmem_cache_destroy mxfs_inode: Slab cache still has objects
      when called from xfs_destroy_caches

    P202-LEAKED-INODE-AT-UNLOAD ino=3272 icount=1 i_state=0x100 mode=040755
      nlink=14 iflags=0x200000 dlm_mode=3 dlm_state=1 ex_h=0 pr_h=0 pin=0
      bast_pending=0 unpublished=0 stale_src=2 bastq_src=1 itemp=1 in_ail=0
      age_ms=46168 dwork_pending=0 dwork_timer=0 bwork_pending=0 demoter=0
      dentries=0 lru_linked=1 sblist_linked=1 hashed=1 wcount=0
    P202-LEAKED-INODE-TOTAL leaked=1 tracked_allocs=1196

`i_state=0x100` = I_REFERENCED only (not I_FREEING/I_CLEAR).
`iflags=0x200000` = `MXFS_IF_DIR_LEAF_STALE` (checked: it IS consumed at
`xfs/libxfs/xfs_dir2.c:601` via `xfs_iflags_test_and_clear`, so its presence
just means no dir-modify followed; not itself a defect).

## THE LINKAGE TO THE DEMOTER CLOBBER IS REFUTED

sess25 recorded D-UNMOUNT-BUSY-INODES as "causally linked to the demoter clobber
3/3 vs 0/4". On the leaking node, in the same window:

    P74-DEMOTER-CONTEST         0
    P76-DEMOTER-FOREIGN-CLEAR   0
    P72-DEMOTER-OVERRIDE        0

Plus the census shows `foreign_clear=0`, `contest=0` cluster-wide on this build —
the clobber is now IMPOSSIBLE (two owned claim slots), and the leak still
happened. **The two defects are independent; fixing D-BAST-IRELE did not fix
this.** Do not re-derive the linkage.

## Also refuted again on the current build

    P204-CANCEL-ARMED-REF   0     (the cancelled-arm ref leak)
    P142-DWORK-LASTREF      0     (the known intentional-leak path)
    P-DBLRECLAIM            0
    P60-BWFN-BADREF         0     (bast_work_fn's trailing-irele refusal)
    P134-ILEND-FREEING      0
    P124-DWFN-BADREF        0

`P76-QW-FALSE = 24` but every one of those paths does an explicit `xfs_irele`.

## Attribution — and a REAL LIMIT on the instrument

    P203-LEVEL[1] xfs_lookup+0x16c/0x1400
    P203-LEVEL[2] xfs_lookup+0x16c/0x1400
    P203-LEVEL[3] site=file1:line26687
    P203-LEVEL[4] site=file1:line27112     (bast_notify ilock-end deferred release)

With `icount=1`, LEVEL[1] is the occupant → `xfs_lookup`. This CONFIRMS sess25's
attribution and shows the `grab_line`/`iget_caller` fields (which named
`mxfs_dlm_bast_notify` / line 27112) are the LAST grab = LEVEL[4], i.e.
misleading — the documented weakness.

**But the LEVEL table is only sound under LIFO release order.** If grab A takes
0->1, grab B takes 1->2, and A releases first (2->1), the surviving reference is
B's while LEVEL[1] still names A. Releases do not rewrite lower levels. So
"xfs_lookup" is PLAUSIBLE, not proven. (The same objection kills the
push/pop P203-GRABSTACK idea, which is also LIFO-assuming — and note
`P203-GRABSTACK` does not exist in the module at all: `strings mxfs.ko` = 0 hits,
yet `tests/unmount_leak_repro.sh` greps for it. Harness/instrument mismatch.)

## Eliminated by code reading (so the next session need not re-walk)

`xfs_lookup` (xfs/xfs_inode.c:1066) releases on every internal path:
- `out_irele:` does `xfs_irele(*ipp)`; `out_unlock:` is only reached from
  line 1226, BEFORE the `xfs_iget` at 1229.
- the type-flip ESTALE path (1768-1770) does `xfs_irele; *ipp = NULL; return`.
- all five `goto retry_iget` sites: 1373 and 1510/1577 release first;
  1301 and 1306 are on the iget-FAILED branch so hold no ref.
`xfs_vn_lookup` (pal/linux/xfs_iops.c:367) hands the ref to `d_splice_alias`,
which consumes it on success AND error — upstream-standard.

So if xfs_lookup really is the leaker, the ref escapes via a caller/VFS path, not
inside xfs_lookup. Combined with `dentries=0`, that is the contradiction to
resolve next.

## Next step

Build an attribution instrument that does NOT assume release order: a per-inode,
per-site BALANCE (grabs minus releases per tagged site) using the existing
`mxfs_igrab_tracked` / `mxfs_iput_tracked` wrappers, which know their site on
BOTH sides. Caveat to design around: refs taken by `xfs_iget` and dropped by the
VFS's plain `iput` are untracked on one or both sides, so a raw imbalance for
xfs_lookup can be a false positive — count tracked-vs-untracked explicitly rather
than inferring.

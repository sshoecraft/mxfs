---
name: unmount-leak-global-refcount-balance-cannot-work
description: DISPROVEN instrument: a global grab/release balance cannot attribute the unmount inode leak — VFS-side iputs are uninstrumentable, so net=78 against…
metadata:
  type: reference
tags: [unmount-busy-inodes, instrument, disproven, refcount, method]
---

# A global grab/release balance cannot attribute the unmount inode leak

## What was tried (sess26) and why it fails

P203-LEVEL names the grab occupying each refcount level but is sound only under
LIFO release order, so it cannot prove who leaked. The proposed replacement was a
per-inode grab/release BALANCE (`P205-REFBAL`, fields `i_mxfs_tgrabs` /
`i_mxfs_tputs`), on the idea that `net == icount` would say whether an XFS/MXFS
grab is unreleased.

Instrumented, in two rounds:

1. First cut counted `mxfs_igrab_tracked` grabs and `mxfs_iput_tracked` releases.
   Captured: **`tgrabs=61 tputs=1 net=60` with `icount=1`** — because MXFS
   releases with `xfs_irele()`, not `iput()`, so almost nothing was counted on
   the release side. The probe still printed a confident verdict
   ("TRACKED-IGRAB-HOLDS-IT"). Wrong.
2. Second cut added the `xfs_irele()` chokepoint (releases) and the `xfs_iget()`
   hand-off (grabs), making it symmetric. Captured:
   **`tgrabs=161 tputs=83 net=78` with `icount=1`.**

Still off by 77. The residue is **VFS-side references**: `dput` -> `iput`,
`evict`, and `d_splice_alias`'s own `iput` on its error path all move the count
without passing either chokepoint, and there is no hook for them short of
patching the VFS.

**Conclusion: the approach is unsound in principle, not merely uncalibrated.**
Linux provides no reverse map from a refcount to its holders, so no
count-based scheme confined to the filesystem can attribute one surviving
reference. Do not rebuild this.

The probe is worth keeping only for its honest third verdict,
`UNEXPLAINED (VFS igrab/iput outside both chokepoints)`, which is what it now
correctly reports.

## Lesson that generalises

Three separate instruments this session produced a confident wrong answer before
being validated (journalctl-only harvest, the loser-vs-peers differential on
rank1, and this balance). **Sanity-check every new counter against a known
invariant before reading a verdict off it** — here the invariant was
`net == icount`, and it failed by 77 on the very first capture.

## What the captures DO establish

Three catches in five cycles at 16/caw on the current build, one node each:

    ino=3272     nlink=14  stale_src=2 bastq_src=1   iflags=DIR_LEAF_STALE
    ino=29360269 nlink=18  stale_src=8 bastq_src=9   iflags=0
    ino=14680218 nlink=18  stale_src=8 bastq_src=14  iflags=0

All three: **DIRECTORY, icount=1, dentries=0, hashed=1, lru_linked=1,
sblist_linked=1, dlm_mode=3(PR), dlm_state=1(CACHED), itemp=1, in_ail=0,
bast/dwork/bwork all not pending, demoter=0.** Attribution converges on
`xfs_lookup+0x16c` from TWO independent fields (`iget_caller` and
`P203-LEVEL[1]`), with `GRAB=file2:line1741/1742` = the ordinary
`xfs_iget_cache_hit` igrab, which names nothing.

`dentries=0` with `icount=1` and no dentry alias is the key contradiction: no VFS
dentry holds it, yet a lookup-obtained reference survives.

## Next experiment (targeted, not global)

Since attribution already points at the lookup hand-off twice independently, test
THAT specifically rather than balancing everything: count, per inode, how many
times `xfs_lookup` returned 0 (handing out a reference) and compare against the
dentry count at unmount. `lookup_handoffs > 0 && dentries == 0 && icount == 1`
would show a lookup reference that no dentry ever took ownership of. Design
around the one legitimate case: `d_splice_alias` consumes the reference via
`iput` on its error paths without ever creating a dentry, so count
`d_splice_alias` outcomes too or the result is ambiguous.

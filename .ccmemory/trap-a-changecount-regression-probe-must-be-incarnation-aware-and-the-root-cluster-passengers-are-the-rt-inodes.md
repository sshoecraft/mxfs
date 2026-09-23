---
name: trap-a-changecount-regression-probe-must-be-incarnation-aware-and-the-root-cluster-passengers-are-the-rt-inodes
description: TRAP (sess582, D-0955): 7 'platter clobber' lines were the survivor's new inodes over the peer's freed numbers (cc restarts per incarnation); the 6 '…
metadata:
  type: feedback
tags: [trap, d0955, inode-cluster, probe]
---

# Two readings of the sole-survivor inode-cluster instruments that were wrong

**1. A changecount is monotonic within an incarnation, not across a
reallocation.** `mxfs_dino_clobber_probe` flagged "memory changecount below
platter" as a revert. On a sole survivor creating files over the departed
peer's freed inode numbers, every flagged slot read
`disk cc=10 mode=0 gen=<random> nlink=0 -> mem cc=4 mode=0100644 gen=<unrelated>`:
the platter holds the peer's FREED image, memory holds the survivor's NEW
file. A new inode starts its changecount at 1 with a fresh random generation,
so this is the allocator working, not a clobber. The regression predicate
needs the incarnation: same generation and behind (BUG2), or the platter
holds the freed successor at generation+1 of the live image we still hold
(the free bumps it by one; publishing ours reverts the free, BUG1).
Anything else is a reallocation. Fixed in the probe with a
`P-DINO-CLOBBER-REALLOC` liveness line. (tests/evidence/20260911T201341Z_d0946disklive_s582h)

**2. "6 unauthorised passenger slots" in the root cluster are the realtime
bitmap and summary inodes.** `P218-CLUSTER-PASSENGER daddr=128 slot=1 ino=129`
and `slot=2 ino=130`, `img_mode=0100000 img_gen=0 img_cc=2 nocore=1`: created
by mkfs, never in core on any node, image unchanged since mkfs. Unauthorised
in the detector's terms (no tenure, no log item), never stale, and the
passenger mask drops them anyway. A P218 count on a workload that writes the
root cluster will always include these two; read the per-slot lines, not the
sum, before calling a passenger a peer's inode.

General: an "unauthorised" count and a "stale" count are different
instruments; only a platter compare answers stale, and it must know which
incarnation it is comparing.

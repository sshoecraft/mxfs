---
name: ccloop-c7ee71c6-sess37-createint-implementation-sketch
description: Ready-to-implement: XFS_ILOCK_MXFS_CREATEINT flag (mirror of existing PRIREAD precedent, xfs_inode.c:302-315) — create-intent lookups take dir EX on…
metadata:
  type: project
---

# CREATEINT implementation sketch (direction A for the create-cycle root)

## Anchor points (verified in-tree, 0.11.317)
1. **Mode mapping + precedent**: xfs/xfs_inode.c ~302-315 inside xfs_ilock:
   `mode = (lock_flags & (IOLOCK_EXCL|ILOCK_EXCL)) ? EX : PR;` followed by the
   PRIREAD downgrade: `XFS_ILOCK_MXFS_PRIREAD && !IOLOCK_EXCL → mode=PR`
   (EXCL-local, PR-wire — "cluster needs PR not EX" for extent-map loads).
   CREATEINT is the exact mirror: SHARED-local, EX-wire.
2. **Intent source**: pal/linux/xfs_iops.c:367 xfs_vn_lookup(dir, dentry,
   unsigned int flags) — flags carries LOOKUP_CREATE/LOOKUP_EXCL (VFS sets
   them for open(O_CREAT) and creation paths; XFS has no atomic_open so
   ->lookup runs first with the intent visible).
3. **Lock site**: the dir ILOCK for lookup is taken INSIDE xfs_dir_lookup
   (libxfs/xfs_dir2.c, via xfs_ilock_data_map_shared(dp)) — plumb a bool
   create_intent from xfs_vn_lookup → xfs_lookup → xfs_dir_lookup (fork-local
   signature changes, all in-tree callers), and there OR the new flag into the
   lock_flags for the dp ILOCK acquire.
4. Flag bit home: wherever XFS_ILOCK_MXFS_PRIREAD is defined (xfs_inode.h lock
   flag block) — take the next free bit, extend xfs_lock_flags_assert masks.

## Why this kills the measured cycle
Per-create today (PROVEN, test5 instr window): lookup-PR (7-CAS storm) → dir
reload → create's EX upgrade → **EDEADLK rc=-35** → PR drop + FULL drain →
fresh EX (rotation wait) → insert. With CREATEINT: the lookup half itself
acquires EX once; ->create's ILOCK_EXCL finds cached EX (already-held
shortcut, zero wire ops). One tenure per create — and with the tenure now
DURABLE across lookup+insert, dir_ex_batch_grace_ms finally has something to
batch (4 creates/wave → potentially 1 tenure/wave → ~32-64 tenures/round vs
today's 214 transitions).

## Cautions
- O_CREAT-on-existing pays EX for a read-shape op — acceptable (rare; caller
  intends write). Plain lookups/stat never carry LOOKUP_CREATE → unaffected.
- Do NOT touch the PRIREAD arm ("never demote a combined IOLOCK_EXCL"). Mirror
  its guard style: CREATEINT only upgrades ILOCK_SHARED, never downgrades.
- After implementing: rerun the test5-style instr window — expect the
  PR,PR,PR→EX per-wave shape to become EX(,cached...) and 'DLM inode lock
  failed rc=-35' count → 0 in create windows. Then dir_reuse ×3 (target ≥9
  rounds for real margin) + full 32-board (create path is hot everywhere).
- Ship with knob (mxfs.create_intent_ex default 1, 0=legacy) per house A/B style.

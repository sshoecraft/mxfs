---
name: sess23-ccloop-suppression-was-corruptor-3of4
description: sess23(ccloop): bnobt double-free ROOT = P122/P93 write-side suppression mis-classified legit coalescing-frees. Disabled it → cache_coherency 0/4→3/4.
metadata:
  type: project
---

# sess23 (ccloop 4eef1f39) — bnobt corruption ROOT FOUND + 3/4 passing

Build `2C16B9C99ED771FF75A8BEB`. cache_coherency went **0/4 → 3/4**.
PASS: cross_visibility, rename_visibility, unlink_visibility. FAIL: cross_write_read.

## THE ROOT (Gemini-confirmed, 2 consults): write-side suppression was the CORRUPTOR
The P122/P93 write-side interlock in `pal/linux/xfs_buf.c` (`mxfs_suppress_stale_agwrite`)
skipped a bnobt/cntbt write whenever **on-disk numrecs > in-core numrecs** (assumed = stale
prior-tenure revert). That discriminator is FUNDAMENTALLY BROKEN: numrecs LEGITIMATELY
DECREASES on a coalescing free (1 freed block bridges 2 free extents → 3 recs merge to 1)
and on an exact-match alloc (whole free-extent record removed). When a node holds the AG,
cold-reads peer's nr=3, then its own rename/unlink frees blocks coalescing bnobt to nr=2,
the in-core nr=2 is CORRECT + AHEAD of disk. Suppressing that write left on-disk bnobt at
nr=3 while cntbt+AGF freeblks DID land → AG-meta set torn in half →
- `xfs_agf_verify` "freeblks != sum(bnobt)" corruption shutdown (xfs_buf.c:1887), AND
- `ltbno+ltlen>bno` in-core double-free (xfs_alloc.c:2244) when a later free hits a block
  the skipped bnobt still lists FREE.

## FIX APPLIED (KEEP)
`pal/linux/xfs_buf.c` ~line 2190: stopped setting `mxfs_suppress_stale_agwrite=true`
(replaced with `(void)p93_inail;(void)p93_dirty;`). P93 detector stays LOG-ONLY. The dead
action block at ~2582 never runs now. Acquire-invalidation + release-drain fences are PROVEN
TIGHT this run (P79=0, P14 trylock-fail=0, P47-preserve=0, P126=0), so NO stale buffer can
reach the write side — suppression was unnecessary AND harmful.

## OTHER CHANGES THIS SESSION (low-risk, keep)
1. `xfs/xfs_mxfs_dlm.c` fresh-acquire: added `mxfs_ag_meta_coldread_discard(pag, true)` after
   invalidate (the sess22 pending edit). Fired 0× — harmless.
2. `pal/linux/xfs_buf_item.c` `xfs_buf_item_push`: added `mxfs_buf_xfsaild_skip_agmeta_write()`
   interception (stale+drop AG-meta when !held in-core). Fired 0× (P126=0) — pushes always
   happen while cached=true. Architecturally-sound failsafe; KEEP. Helper in xfs_mxfs_dlm.c.

## REFUTED theories this session
- "xfsaild pushes during peer tenure (held=0)": P126=0, ALL pushes held=1/cached=true.
- "stale prior-tenure in-AIL buffer survives acquire fence": P79/P14/P47=0, none present.
- "FUA reads stale platter": fua_disable=1 (default), reads are PLAIN=coherent.

## NEXT: cross_write_read (only remaining fail)
1-2 failures of 6 assertions/node. Each node verifies node2/3/4 integrity OK but the FAIL is
node1-related (node1 missing from OK lists). dmesg shows shutdown count=1 on all nodes —
investigate whether a real shutdown still occurs at/after cross_write_read (could be node1
md5 mismatch = writer-durability/reader-staleness for regular-file content, a DIFFERENT path
from the bnobt fix — see sess79/sess85/sess45 reg-file BAST-release flush + di_size).
Re-run after clean power-cycle (virsh destroy+start ALL 4) + tests/reset4.sh 4.
Marker NOT written (cross_write_read still fails).</body>

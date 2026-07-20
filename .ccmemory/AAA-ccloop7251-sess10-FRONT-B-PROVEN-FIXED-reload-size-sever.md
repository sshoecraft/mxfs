---
name: AAA-ccloop7251-sess10-FRONT-B-PROVEN-FIXED-reload-size-sever
description: FRONT B ROOT PROVEN+FIXED: reload_identical path re-synced VFS i_size down to lagging i_disk_size mid-append → writeback clamp → durable size=0. relo…
metadata:
  type: project
tags: [ccloop-72513a13, sess10, front-b, data-loss, fixed]
---

# Front B (drc@32 extending-write size=0) — ROOT PROVEN + FIXED sess10

## Mechanism (RULE-4 live-proven, test16 ino=16777344, build C9087863)
1. drc writer mid-append: VFS i_size=16384 (of eventual 20480), i_disk_size=0
   (6.19 maps data-fork writeback as UNWRITTEN — `bma.flags=XFS_BMAPI_PREALLOC`
   in xfs_bmapi_convert_one_delalloc; di_size advances ONLY in
   xfs_iomap_write_unwritten via xfs_new_eof, which CLAMPS to VFS i_size.
   xfs_setfilesize is effectively DEAD CODE for buffered appends here — P-SFS
   proved 0 calls over full drc runs).
2. Grant bounce mid-write → reload (state=ACQUIRING) → disk dinode identical
   (size=0) or P34F dirty-skip forces reload_identical=1 → fork kept, BUT
   xfs_mxfs_dlm.c ~19354 `i_size_write(VFS_I(ip), ip->i_disk_size)` still ran
   → VFS i_size 16384→0 (P-RELOAD-SIZESEVER probe).
3. Writeback converts first extent: P-WU-CLAMP end=4096 vfs=0 → xfs_new_eof=0
   → di_size never advances; remaining dirty pages beyond-EOF discarded;
   delalloc punched at evict → durable size=0 nx=0. sync(2) swallows all of it.

## Fix (0.11.36 lineage, param runtime-writable 0644)
`mxfs_reload_size_keep=1` (DEFAULT in code now): skip the VFS-size re-sync when
reload_identical (from_disk skipped ⇒ i_disk_size is OURS ⇒ VFS authoritative).
The sess25 sync stays for genuine adopts (!identical); P34F forces identical
whenever local dirty data exists, so every dirty case is protected.
Validation: knob=0 run reproduced loss with both probes on the failing ino;
knob=1 run: content 43/43 clean, 5 severs averted (test16 ×3, test32 ×2).

## Probes live in tree (caps 300-1500)
- P-RELOAD-SIZESEVER (xfs_mxfs_dlm.c pre-19354): reload would shrink VFS size
  below dirty/delalloc/writeback state; prints ident/keep.
- P-WU-CLAMP (pal/linux/xfs_iomap.c write_unwritten): conversion covers bytes
  beyond di_size but new_eof refused — the durable-short signature.
- P-SFS (pal/linux/xfs_aops.c xfs_setfilesize): both arms incl. clamped no-op.
- P-IOEND-ERR (xfs_end_ioend): errored ioend ends writeback w/o setfilesize.

## Remaining drc@32 red: pace only (6 rounds/116-128s vs MIN 8) = Front A
(round-open handoff staircase; BASTs arrive 22-75µs after grant, holder's
ACQUIRING-deferred honor path sleeps full 300ms window).

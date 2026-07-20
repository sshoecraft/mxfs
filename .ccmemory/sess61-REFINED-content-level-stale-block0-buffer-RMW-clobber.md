---
name: sess61-REFINED-content-level-stale-block0-buffer-RMW-clobber
description: sess61 REFINED: dir_reuse 4-node loss = EX holder RMWs a CONTENT-stale in-core block0 BUFFER (core_node1=0 while disk_node1=76), metadata (fmt/nx/siz…
metadata:
  type: project
---

## sess61 REFINED root — content-level stale block0 buffer RMW (supersedes the format-conversion framing for the CURRENT dominant face)

### My sess61 fix ATTEMPT was REFUTED
`mxfs_dir_modify_adopt_disk_format()` (xfs_mxfs_dlm.c, called in xfs_create at
xfs_inode.c ~1492): FUA-reads the dinode; if in-core fork format/nextents/size
is BEHIND disk for the same di_gen, drop+reload+retake ILOCK. Built (289E7862 /
A2C435A6). P61-ADOPT-CHK diagnostic shows it is CALLED every create but
**incore_fmt=2 disk_fmt=2 (both EXTENTS) on 100/100, never gen-mismatch, never
disk-ahead in nx/size** => the condition never triggers. P61-ADOPT-DISK=0.
Failures persist (same/more rounds). The EX holder's inode METADATA is never
behind disk (it holds EX, in-core >= disk for fmt/nx/size).

### The ACTUAL staleness is CONTENT-LEVEL, in the cached DATA BLOCK buffer
Decisive create-time (comm=dd, dlm_mode=5 EX) P61-BLK0 (block0 content scan,
in-core vs FUA disk, counting "node1" dirent name bytes):
  test4: core_node1=0  disk_node1=76   (daddr 33491656)
  test4: core_node1=13 disk_node1=14
  test2: core_node1=0  disk_node1=5  and  core_node1=0 disk_node1=19
  test1: core_node1=11 disk_node1=0  (in-core AHEAD = legit own work)
So the EX holder's in-core block0 BUFFER content is BEHIND disk (often EMPTY,
core=0) while the inode metadata matches. It RMWs that stale buffer and writes
it back, clobbering disk's dirents (node1_f1 etc.). At VERIFY (PR) the block is
coherent (core==disk) because the sess60 readdir gen-bump re-reads — the damage
is already durable by then.

The node does NOT re-convert: P61-ADOPT-CHK shows it NEVER holds shortform
(igets the dir already in block/EXTENTS format). So the earlier sess61 "stale
shortform re-conversion" was one face seen in a faster-timing run; the steady
dominant face is a **stale cached EXTENTS block0 buffer** (content behind disk,
sometimes empty = possible prior-incarnation ABA or freshly-alloc'd-unfilled).

### Why the existing machinery doesn't catch it
mxfs_dir_evict_data_blocks (modify path, force_evict=1 so it runs every modify)
KEEPS a block0 buffer that is "undurable" (dirty / in-AIL-undestaged / pinned /
!DONE) to protect own work. sess41 added an evict-side refresh that, for a
block KEPT ONLY because in-AIL-undestaged (clean, not dirty), FUA-compares disk
and drops XBF_DONE if disk has STRICTLY MORE live dirents. GAP: a genuinely
DIRTY block0 buffer that is content-behind-disk is still kept (the refresh skips
dirty/pinned/delwri). That dirty-but-stale (often empty) block0 is the clobber.

### Open question for next step / consult
How to safely handle a DIRTY in-core block0 buffer whose content is BEHIND disk
(disk has peer dirents we lack) on the EX modify path: a blind drop loses own
un-checkpointed work + risks the iflush in-memory-corruption shutdown; the
correct op is a UNION-MERGE of disk + in-core dirents (cf. sess17 block-level
union-merge). OR this is a DLM double-grant (two nodes EX at once: in-core can
only be behind disk under EX if a peer wrote while we held EX = concurrent EX) —
needs cross-node EX-overlap check (sess49 TCP double-grant residual). Verify
which before designing the fix.

Instrumentation in tree (KEEP for now): P61-BLK0 (xfs_da_btree.c after block
read, bno==0, in-core vs FUA disk node1 count), P61-ADOPT-CHK/DISK
(xfs_mxfs_dlm.c), per-failure dmesg snapshot in tests/suite/dir_reuse_coherency.sh
-> /root/drc_fail_r${round}_rank${R}.dmesg. See
[[sess61-PROVEN-ROOT-stale-shortform-reconversion-clobbers-disk-block-dir]],
[[sess49-residual-tcp-doublegrant-dir-resurrection-complete-diagnosis]],
[[sess17-CONFIRMED-staleflush-clobber-P17]].</body>

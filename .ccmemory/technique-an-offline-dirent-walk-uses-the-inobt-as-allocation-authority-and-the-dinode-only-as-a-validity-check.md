---
name: technique-an-offline-dirent-walk-uses-the-inobt-as-allocation-authority-and-the-dinode-only-as-a-validity-check
description: TECHNIQUE (D-0964, 0.88.1, Astra ruling): a checker's dirent walk resolves names against the inobt set, never a convincing dinode; report-only; parsi…
metadata:
  type: feedback
tags: [chk_mxfs, directory, checker, D-0964, astra]
---

# An offline directory-entry walk: what the oracle is and what a hand parser gets wrong

**Why it exists (D-0964):** chk_mxfs parsed no directory name, so a published dirent naming a
freed inode (D-0963's durable outcome: lists on every node, resolves on none, `rm` cannot remove
it) reported CLEAN. The board's chk_clean row could not catch the class it exists for.

**The oracle (Astra ruling 2026-09-19):** the inobt is the allocation authority (a holemask bit
covers FOUR inode positions; a free_mask bit one); the dinode is a SEPARATE validity check (magic,
v3, `di_ino`, CRC, mode != 0). "Inobt free but the dinode looks allocated" is still a dangling
entry: freed inode bytes are not erased. `di_nlink` is never an allocation criterion —
open-unlinked inodes are allocated at nlink 0. A dirent carries no generation, so a stale name
that now points at a reallocated inode of the same type is invisible to this pass.

**Parsing traps (from the ruling, all real):**
- `XFS_DIR2_LEAF_OFFSET` is 32 GiB of BYTES: compare bmbt logical offsets against 32 GiB /
  fsblocksize, directory-block numbers against 32 GiB / dirblocksize; they differ when
  `sb_dirblklog != 0`, and a directory block may span extents — assemble it through the extent
  map; a partially mapped one is reported, never walked.
- The interior bmbt pointer array is based at the block's CAPACITY (`(blocksize-72)/16`, or
  `(forksize-4)/16` in the bmdr root), not at `numrecs`.
- XDB3 tail `count` INCLUDES stale slots (`stale <= count`); data ends at
  `dbsize - 8 - count*8`. XDD3 data ends at the block end. Records must partition the data area
  exactly; each record's and each unused span's tag points back at its own offset.
- Shortform: `i8count != 0` widens EVERY number including the parent; entries are packed (no
  8-alignment); the 2-byte entry offset is not "next record"; the entries must end exactly at
  `di_size`; the parent IS the `..` reference (an empty shortform dir still has one to check).
- `di_format == BTREE` (extent map) and "node-format directory" (hash index) are unrelated.
- ftype: map S_IFMT to the XFS ftype enum, range-check the byte, treat 0 as unspecified, and
  never trust the ftype over the dinode.

**Coverage:** print counts on every exit path; zero directories or a root never walked is an
error; every skipped directory / bad block is an error so a skip can never yield CLEAN.

**Repair:** report-only under `-a` (bestfree, hash index and free index must be maintained, and
the name is the evidence). A later minimal repair starts with ordinary non-dot shortform entries
on an exclusively owned image.

**Live LUN caveat:** dirent, inobt and dinode can be from different moments; the offline
(unmounted) rows are the authoritative ones. Harness: `tests/d0964_chk_dangling_dirent.sh`.

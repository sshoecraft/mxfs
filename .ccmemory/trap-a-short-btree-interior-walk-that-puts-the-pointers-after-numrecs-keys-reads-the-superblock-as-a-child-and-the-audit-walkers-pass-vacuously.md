---
name: trap-a-short-btree-interior-walk-that-puts-the-pointers-after-numrecs-keys-reads-the-superblock-as-a-child-and-the-audit-walkers-pass-vacuously
description: TRAP (s69a→s70a, 0.89.7): chk_mxfs put a btree node's child ptrs at hdr+numrecs*keylen; XFS uses hdr+MAXRECS*keylen. First 2-level inobt (>16128 inod…
metadata:
  type: feedback
tags: [chk_mxfs, btree, checker, false-verdict, vacuous]
---

# A short-format btree interior walk that places the pointers after `numrecs` keys reads the superblock as a child, and the audit walkers pass vacuously

**Where it bit:** tools/chk_mxfs.c, all five interior-node walkers (walk_freespace_btree, walk_inobt, orphan_walk_inobt, ds_walk_inobt, de_walk_inobt), s69a on 0.89.6; fixed 0.89.7.

**The layout fact:** for a V5 short-format btree block (56-byte CRC header), the keys start at byte 56 and the child pointers start at `56 + MAXRECS * keylen`, where MAXRECS = (blocksize - 56) / (keylen + 4). That is the kernel's `xfs_btree_ptr_offset()` (block_len + get_maxrecs * key_len + (n-1) * ptr_len). At 4 KiB: inobt/finobt (4-byte keys) ptrs at byte 2076; bnobt/cntbt (8-byte keys) ptrs at byte 2744. `56 + numrecs * keylen` lands inside the UNUSED key slots, which are zero on a freshly split node.

**What that produced:** child agbno 0 → the walk read the AG's block 0, the XFS superblock, and reported `magic expected 0x49414233 (IAB3), got 0x58465342 (XFSB)` plus a CRC failure for each child; every count derived from the walk was then wrong (inobt total 0 vs AGI count 20224; fs inobt sum 64 vs icount 20288). Ten errors on a platter both nodes had just unmounted cleanly.

**Why it had never fired:** no test filesystem had more than one inobt leaf per AG (252 chunk records = 16128 inodes at 4 KiB). The s69a filesystem carried 20224 inodes in AG 0 from the residue of earlier laps, so the level-1 arm ran for the first time.

**The two failure directions:** walk_inobt/walk_freespace_btree print errors (noisy, false positive). The three audit walkers (orphan, dangling-parent, dirent) `return` silently on a magic mismatch, so on a two-level inobt the orphan audit printed `OK (0 allocated inodes, 0 on unlinked buckets)` — a vacuous pass — and only the dirent walk's own vacuity gate ("no directory was walked") turned it into an error. A walker that returns silently on a bad block makes a false CLEAN, not a false CORRUPT. Any earlier chk_mxfs verdict on an AG with >16128 inodes or >505 free extents was read through this defect.

**How it was proven before patching:** direct read of the root block from a node (`dd iflag=direct` of LUN block xfs_data_offset/4096 + agbno): IAB3, level 1, numrecs 2; keys 128/8832 at byte 56; zeros at byte 64 (where the walk looked); pointers 3/2178 at byte 2076.

**The harness lesson:** tests/chk_mounted_node_reads_platter.sh s69a PASSed all its own assertions (they were about the icount line) while the checker printed ten errors and rc 4. A harness that runs a verifier on a quiescent platter must assert the verifier's verdict (rc 0, zero ERROR lines), not just the one field it came for — otherwise the verifier's own defect rides through the lap as a PASS. Also: when grepping a checker log for `AG 0 inobt`, anchor the pattern (`AG 0 inobt btree\|AG 0 inobt \.\.`) — the per-record lines match too and flood the context.

---
name: xfs_native_format_plan
description: Native XFS on-disk format plan for mkfs.mxfs — the design that produced the current envelope layout.
metadata:
  type: project
---

# Native XFS Format Plan for mkfs.mxfs

## Goal
Replace `system("mkfs.xfs -f -d size=... device")` in mkfs_mxfs.c with a native
`format_xfs_native(fd, xfs_data_size, uuid_out)` function that writes a minimal
valid XFS v5 filesystem directly. No external dependency on xfsprogs.

## Reference Image
A minimal-feature XFS v5 image exists at `/tmp/xfs_minimal.img` (256MB, loop device).
Created with: `mkfs.xfs -f -m finobt=0,rmapbt=0,reflink=0,bigtime=0`

## Fixed Parameters
- blocksize = 4096, blocklog = 12
- sectsize = 512, sectlog = 9
- inodesize = 512, inodelog = 9
- inopblock = 8, inopblog = 3
- inoalignmt = 8
- spino_align = 4
- XFS_INODES_PER_CHUNK = 64
- inode_chunk_blocks = 8 (64 * 512 / 4096)
- imax_pct = 25
- rextsize = 1
- dirblklog = 0

## Feature Flags
- sb_versionnum = 0xB4A5
  (v5 | NLINK | ALIGN | LOGV2 | EXTFLG | DIRV2 | MOREBITS)
  Note: 0xB4A5 NOT 0xB4B5 — ATTRBIT (0x0010) is NOT set (ATTR2 supersedes it)
  Actually 0xB4A5 = 1011_0100_1010_0101. Bits: 15,13,12,10,7,5,2,0.
  = MOREBITS(15) | DIRV2(13) | EXTFLG(12) | LOGV2(10) | ALIGN(7) | NLINK(5) | bits 2,0 of version 5
- sb_features2 = 0x018A
  (LAZYSBCOUNT=0x02 | ATTR2=0x08 | PROJID32=0x80 | CRC=0x100)
- sb_bad_features2 = 0x018A (duplicate)
- sb_features_compat = 0
- sb_features_ro_compat = 0 (no FINOBT/RMAPBT/REFLINK)
- sb_features_incompat = 0x03 (FTYPE=0x01 | SPINODES=0x02)
- sb_features_log_incompat = 0

## Geometry Calculation
Given xfs_data_size in bytes:
```
dblocks = xfs_data_size / 4096
agcount = max(1, dblocks / 262144)  // target ~1GB per AG
if agcount < 2: agcount = 2         // need at least 2 for log placement
agblocks = dblocks / agcount        // blocks per AG (last AG may be smaller)
// Last AG size:
last_ag_blocks = dblocks - (agcount - 1) * agblocks
// Ensure last AG >= 64 blocks (minimum viable)
agblklog = ceil(log2(agblocks))
```

Log placement:
```
log_ag = agcount / 2               // middle AG
log_start_block = 8                // after AG header(0) + btrees(1-3) + AGFL(4-7)
logblocks = clamp(dblocks/2048, 512, 65536)  // 2MB to 256MB
// Ensure log fits in the log AG
if log_start_block + logblocks > agblocks:
    logblocks = agblocks - log_start_block - 16  // leave room for AGFL + free
logstart = log_ag * agblocks + log_start_block   // absolute FSB
```

Root inode:
```
// Inode chunk at first inoalignmt-aligned block after btrees+AGFL in AG 0
inode_chunk_start = 8  // blocks 0-3 = headers+btrees, 4-7 = AGFL
rootino = inode_chunk_start * inopblock = 8 * 8 = 64
rbmino = 65
rsumino = 66
```

## Per-AG Block Layout

### Non-log, non-AG0 AGs (e.g., AG 1, AG 3):
- Block 0: SB + AGF + AGI + AGFL (sectors 0-3 of one 4KB block)
- Block 1: BNO btree root
- Block 2: CNT btree root
- Block 3: INO btree root
- Blocks 4-7: AGFL reserved blocks
- Block 8+: free space
- freeblks = agblocks - 8, longest = agblocks - 8
- BNO record: [startblock=8, blockcount=agblocks-8]
- CNT record: [startblock=8, blockcount=agblocks-8]

### AG 0 (has inode chunk):
- Block 0: SB + AGF + AGI + AGFL
- Blocks 1-3: BNO, CNT, INO btree roots
- Blocks 4-7: AGFL reserved
- Blocks 8-15: inode chunk (64 inodes)
- Block 16+: free space
- freeblks = agblocks - 16, longest = agblocks - 16
- BNO record: [startblock=16, blockcount=agblocks-16]
- AGI: count=64, freecount=61, root=3, level=1, newino=64
- INO btree: 1 record [startino=64, holemask=0, count=64, freecount=61, free=0xFFFFFFFFFFFFFFF8]

### Log AG (e.g., AG 2):
- Block 0: SB + AGF + AGI + AGFL
- Blocks 1-3: BNO, CNT, INO btree roots
- Blocks 4-7: log starts here (shared with what would be AGFL space)

Wait — from the reference, logstart = AG2 block 4. And the AGFL for AG2 contains blocks
AFTER the log. Let me re-examine:
- AG 2 BNO free space starts at block log_start_block + logblocks
- Need 4 AGFL blocks from that free area
- AGFL entries = [first_free, first_free+1, first_free+2, first_free+3]
- Free starts at first_free + 4

So for AG 2:
- Blocks 0-3: headers + btrees
- Blocks 4 to 4+logblocks-1: log
- Blocks 4+logblocks to 4+logblocks+3: AGFL
- Blocks 4+logblocks+4 to agblocks-1: free space
- freeblks = agblocks - 4 - logblocks (includes AGFL blocks in count)
  Wait no. AGF freeblks does NOT include AGFL blocks.
  freeblks = agblocks - 4 (btrees+header) - logblocks - 4 (AGFL)
  Hmm, actually: freeblks = agblocks - (1 header block + 3 btree blocks + logblocks)
  The AGFL blocks are part of the AG but tracked separately.

  Actually from the reference:
  AG 0: freeblks = 32752 = 32768 - 16. 16 = 1(hdr) + 3(btree) + 4(AGFL) + 8(inodes) = 16.
  But AGFL blocks (4-7) are counted IN freeblks. Let me re-check...

  AG 1: freeblks = 32760 = 32768 - 8. 8 = 1(hdr) + 3(btree) + 4(AGFL)? But 32768-8=32760.
  Hmm, that's 8 blocks used. But AGFL has 4 blocks (4,5,6,7). So: 1+3+4=8? But then
  where is the free space record? BNO says startblock=8, blockcount=32760.
  So free space is blocks 8-32767 = 32760 blocks. And freeblks=32760. So freeblks
  includes the AGFL blocks? NO — the free space starts at block 8, meaning blocks 0-7
  are ALL used (header + btrees + AGFL reserves), and freeblks=32760 = the actual free
  blocks NOT including AGFL reserves.

  AG 2: freeblks = 16376 = 32768 - 16392. 16392 = 1+3+logblocks(16384)+4(AGFL) = 16392.
  Free start: 16392. blockcount = 32768 - 16392 = 16376. Matches.

So the formula:
- used = 4 (header + btrees) + logblocks_in_this_AG + inode_chunk_blocks_in_this_AG + 4 (AGFL)
- freeblks = agblocks - used
- BNO/CNT record: [startblock=used, blockcount=freeblks]

Wait, that doesn't work for AG 2. Let me re-check:
AG 2: 4 (hdr+btree) + 16384 (log) + 4 (AGFL) = 16392. blocks 0-3 = hdr+btree,
blocks 4-16387 = log, blocks 16388-16391 = AGFL, blocks 16392+ = free.
freeblks = 32768 - 16392 = 16376. BNO: [16392, 16376]. YES matches.

AG 0: 4 (hdr+btree) + 4 (AGFL) + 8 (inodes) = 16. blocks 0-3 = hdr+btree,
blocks 4-7 = AGFL, blocks 8-15 = inodes, blocks 16+ = free.
freeblks = 32768 - 16 = 32752. BNO: [16, 32752]. YES matches.

AG 1,3: 4 (hdr+btree) + 4 (AGFL) = 8. blocks 0-7 used.
freeblks = 32768 - 8 = 32760. BNO: [8, 32760]. YES matches.

## On-Disk Structure Byte Layouts

### Superblock (512 bytes, at sector 0 of each AG's block 0)
All big-endian except CRC (__le32).

Primary SB (AG 0):
- Set all fields as described in the field table above
- icount=64, ifree=61, fdblocks=sum of all AG freeblks
- rootino=64, rbmino=65, rsumino=66
- inprogress=0

Secondary SBs (AG 1+):
- Same as primary EXCEPT:
  - rootino=0xFFFFFFFFFFFFFFFF (NULLFSINO)
  - rbmino=0xFFFFFFFFFFFFFFFF
  - rsumino=0xFFFFFFFFFFFFFFFF
  - inprogress=1
  - icount=0, ifree=0
  - fdblocks may differ slightly (reference shows different values but let's use same)
- Different CRC (computed per-SB)

### AGF (512 bytes, at sector 1 of each AG's block 0)
```
Offset  Size  Field          Value
0x00    4     magicnum       0x58414746
0x04    4     versionnum     1
0x08    4     seqno          AG number
0x0C    4     length         agblocks (or last_ag_blocks for last AG)
0x10    4     bnoroot        1
0x14    4     cntroot        2
0x18    4     rmaproot       0 (disabled)
0x1C    4     (padding)      0
0x20    4     bnolevel       1
0x24    4     cntlevel       1
0x28    4     rmaplevel      0
0x2C    4     (padding/refcntlevel) 0
0x30    4     flfirst        1
0x34    4     fllast         4
0x38    4     flcount        4
0x3C    4     freeblks       (calculated per AG)
0x40    4     longest        (same as freeblks for single-extent AG)
0x44    4     btreeblks      0
0x48    16    uuid           (FS UUID)
0x58-0xD7     zeros (padding)
0xD8    8     lsn            0
0xDC    4     crc            (computed, __le32)
0xE0-0x1FF   zeros
```
Wait, CRC offset. From the reference hex dump, CRC is at byte 0xDC within the AGF sector
(which starts at 0x200 in the block). Actually, looking at the kernel struct:
```
struct xfs_agf {
    __be32  agf_magicnum;       // 0
    __be32  agf_versionnum;     // 4
    __be32  agf_seqno;          // 8
    __be32  agf_length;         // 12
    __be32  agf_roots[2];       // 16 (bnoroot, cntroot) - WAIT
```
Actually the kernel uses arrays for some fields. Let me use the actual byte offsets from
our verified reference dump:

Actually, looking at the reference AGF dump more carefully:
```
0x200: 5841 4746 0000 0001 0000 0000 0000 8000  XAGF............
0x210: 0000 0001 0000 0002 0000 0005 0000 0001  ................
0x220: 0000 0001 0000 0001 0000 0001 0000 0006  ................
0x230: 0000 0006 0000 7feb 0000 7fe8 0000 0000  ................
```
Wait, that's the FULL-FEATURE reference (with rmapbt). The minimal-feature reference
has different values. From the minimal reference:
- bnoroot=1, cntroot=2, rmaproot=0
- bnolevel=1, cntlevel=1, rmaplevel=0
- flfirst=1, fllast=4, flcount=4
- AG0: freeblks=32752, longest=32752

The AGF on-disk layout (kernel struct byte offsets within the AGF sector):
```
0x00: magicnum (4)
0x04: versionnum (4)
0x08: seqno (4)
0x0C: length (4)
0x10: roots[0] = bnoroot (4)
0x14: roots[1] = cntroot (4)
0x18: roots[2] = rmaproot (4)   // XFS_BTNUM_RMAPi=2
0x1C: spare0 (4)                // padding
0x20: levels[0] = bnolevel (4)
0x24: levels[1] = cntlevel (4)
0x28: levels[2] = rmaplevel (4)
0x2C: spare1 (4)                // padding (was refcntlevel in some layouts)
0x30: flfirst (4)
0x34: fllast (4)
0x38: flcount (4)
0x3C: freeblks (4)
0x40: longest (4)
0x44: btreeblks (4)
0x48: uuid (16)
0x58: rmap_blocks (4)
0x5C: refcount_blocks (4)
0x60: refcount_root (4)
0x64: refcount_level (4)
0x68: spare64[14] (112)
0xD8: lsn (8)
0xE0: crc (4, __le32!)
0xE4: spare2 (4)
Total: 232 used, padded to 512
```
CRC at offset 0xE0 within the AGF sector (= absolute offset 0x2E0 in block 0).
CRC covers bytes 0x00-0x1FF of the AGF sector (full 512 bytes) with CRC field zeroed.

### AGI (512 bytes, sector 2)
```
0x00: magicnum (4) = 0x58414749
0x04: versionnum (4) = 1
0x08: seqno (4) = AG number
0x0C: length (4) = agblocks
0x10: count (4) = 64 for AG0, 0 for others
0x14: root (4) = 3 (inobt root block)
0x18: level (4) = 1
0x1C: freecount (4) = 61 for AG0, 0 for others
0x20: newino (4) = 64 for AG0, 0xFFFFFFFF for others
0x24: dirino (4) = 0xFFFFFFFF
0x28: unlinked[64] (256) = all 0xFFFFFFFF
0x128: uuid (16)
0x138: crc (4, __le32!)
0x13C: pad32 (4)
0x140: lsn (8)
0x148: free_root (4) = 0 (finobt disabled)
0x14C: free_level (4) = 0
0x150: ino_blocks (4) = 0
0x154: fino_blocks (4) = 0
0x158+: zeros to 0x1FF
```
CRC at offset 0x138 within the AGI sector. Covers full 512 bytes.

### AGFL (512 bytes, sector 3)
```
0x00: magicnum (4) = 0x5841464C
0x04: seqno (4) = AG number
0x08: uuid (16)
0x18: lsn (8)
0x20: crc (4, __le32!)
0x24: bno[0] (4) = 0xFFFFFFFF (unused, before flfirst)
0x28: bno[1] (4) = first AGFL block
0x2C: bno[2] (4) = second AGFL block
0x30: bno[3] (4) = third AGFL block
0x34: bno[4] (4) = fourth AGFL block
0x38+: bno[5-118] = all 0xFFFFFFFF
```
119 entries from 0x24 to 0x1FF. CRC at offset 0x20. Covers full 512 bytes.

### V5 Btree Block Header (56 bytes, for BNO/CNT/INO roots)
```
0x00: magic (4) = see below
0x04: level (2) = 0 (leaf)
0x06: numrecs (2) = number of records
0x08: leftsib (4) = 0xFFFFFFFF (null)
0x0C: pad (4) = 0 (required for v5 packing)
0x10: rightsib (4) = 0xFFFFFFFF (null)
0x14: pad (4) = 0
0x18: blkno (8) = disk address in 512-byte sectors (block_number * 8)
0x20: lsn (8) = 0
0x28: uuid (16)
0x38: owner (4) = AG number
0x3C: crc (4, __le32!)
--- records start at offset 0x40 (64 bytes) ---
WAIT: from reference, the header is 56 bytes (0x38), not 64. Let me re-check.
```

Actually, looking at the reference dump: BNO record at offset 0x38 within the block.
Header fields:
```
0x00: magic (4)
0x04: level (2)
0x06: numrecs (2)
0x08: leftsib (4) = 0xFFFFFFFF
0x0C: rightsib (4) = 0xFFFFFFFF
--- v5 extension ---
0x10: blkno (8) = disk addr in 512B sectors
0x18: lsn (8) = 0
0x20: uuid (16)
0x30: owner (4) = AG number
0x34: crc (4, __le32!)
--- records at 0x38 ---
```
Wait that's only 56 bytes (0x38). But earlier research said 64. Let me look at the
reference hex more carefully.

From the reference BNO dump (AG 0):
```
Block 1, offset 0x1000:
0x00: 41423342  magic = AB3B
0x04: 0000      level = 0
0x06: 0001      numrecs = 1
0x08: FFFFFFFF  leftsib
0x0C: FFFFFFFF  rightsib
0x10: 00000000 00000008  blkno = 8 (block 1 * 8 sectors)
0x18: 00000000 00000000  lsn = 0
0x20: [16 bytes uuid]
0x30: 00000000  owner = 0 (AG 0)
0x34: [4 bytes CRC]
0x38: record data starts here
```

So v5 short-form btree header = 56 bytes (0x38). Records start at offset 56.

WAIT — the reference from the Explore agent said "XFS_BTREE_SBLOCK_CRC_SIZE 56" and
the reference from the general agent said header is 56 bytes with leftsib/rightsib at
offsets 8/12 (4 bytes each). But looking at the kernel code:

```c
struct xfs_btree_block {
    __be32      bb_magic;           // 0
    __be16      bb_level;           // 4
    __be16      bb_numrecs;         // 6
    union {
        struct {                    // short form (AG btrees)
            __be32 bb_leftsib;      // 8
            __be32 bb_rightsib;     // 12
        };
    };
    // v5 CRC extension:
    __be64      bb_blkno;           // 16
    __be64      bb_lsn;             // 24
    uuid_t      bb_uuid;            // 32
    __be32      bb_owner;           // 48
    __le32      bb_crc;             // 52
};
// Total: 56 bytes
```

So header size = 56 bytes for v5 short-form btree. This is XFS_BTREE_SBLOCK_CRC_SIZE.

BNO/CNT record format (leaf): {startblock(be32), blockcount(be32)} = 8 bytes each.
INO record format: {startino(be32), holemask(be16), count(u8), freecount(u8), free(be64)} = 16 bytes.

Magic numbers:
- BNO: 0x41423342 ("AB3B")
- CNT: 0x41423343 ("AB3C")
- INO: 0x49414233 ("IAB3")

CRC covers the entire 4096-byte block with CRC field at offset 52 zeroed.

### Root Inode (512 bytes, v3 format)
```
0x00: magic (2) = 0x494E
0x02: mode (2) = 0x41ED (040755)
0x04: version (1) = 3
0x05: format (1) = 1 (XFS_DINODE_FMT_LOCAL)
0x06: onlink (2) = 0
0x08: uid (4) = 0
0x0C: gid (4) = 0
0x10: nlink (4) = 2
0x14: projid_lo (2) = 0
0x16: projid_hi (2) = 0
0x18: padding (8) = 0
0x20: atime (8) = current time
0x28: mtime (8) = current time
0x30: ctime (8) = current time
0x38: size (8) = 6 (short-form dir with just parent pointer, no entries)
0x40: nblocks (8) = 0
0x48: extsize (4) = 0
0x4C: nextents (4) = 0
0x50: naextents (2) = 0
0x52: forkoff (1) = 0
0x53: aformat (1) = 2 (XFS_DINODE_FMT_EXTENTS for attr fork)
0x54: dmevmask (4) = 0
0x58: dmstate (2) = 0
0x5A: flags (2) = 0
0x5C: gen (4) = 0
--- v3 extension ---
0x60: next_unlinked (4) = 0xFFFFFFFF
0x64: crc (4, __le32!)
0x68: padding (4) = 0
0x6C: changecount (4) = 2   (NOTE: only 4 bytes, not 8)
WAIT, from the kernel:
```
Actually the v3 inode extension after offset 0x60:
```
0x60: di_next_unlinked (4) = 0xFFFFFFFF
--- v3 CRC extension ---
0x64: di_crc (4, __le32!)
0x68: di_changecount (8)
0x70: di_lsn (8)
0x78: di_flags2 (8)
0x80: di_cowextsize (4)
0x84: di_pad2[12] (12)
0x90: di_crtime (8) = current time
0x98: di_ino (8) = inode number
0xA0: di_uuid (16) = FS UUID
--- data fork starts at 0xB0 (176 bytes) ---
```

Root directory inline data (at offset 0xB0):
Short-form directory header:
```
0xB0: count (1) = 0 (no entries besides implied . and ..)
0xB1: i8count (1) = 0 (4-byte inode numbers)
0xB2: parent (4) = rootino (64, big-endian: 0x00000040)
```
Total dir data = 6 bytes. di_size = 6.

CRC covers full 512 bytes of the inode with CRC field at offset 0x64 zeroed.

### Free Inodes (inodes 65-66 = rbmino/rsumino, and 67-127 = truly free)

rbmino (65) and rsumino (66) are "allocated" (bit clear in free bitmap) but have:
- magic = 0x494E, version = 3
- mode = 0 (unallocated appearance but counted as allocated)
- format = 0 (XFS_DINODE_FMT_DEV)
- All other fields = 0 except:
  - next_unlinked = 0xFFFFFFFF
  - crc = valid
  - ino = self (65/66)
  - uuid = FS UUID

Free inodes (67-127) are similar but truly unallocated:
- magic = 0x494E, version = 3, mode = 0, format = 0
- next_unlinked = 0xFFFFFFFF
- crc = valid
- ino = self
- uuid = FS UUID
- Everything else = 0

### Log Area
From the reference, the log has a proper FEEDBABE header. However, XFS kernel can handle
an entirely zeroed log (xlog_find_zeroed() returns -ENOENT, mount continues with fresh log).

For safety, let's write the proper log header:
First 512-byte sector of log:
```
0x00: magic (4) = 0xFEEDBABE
0x04: cycle (4) = 1
0x08: version (4) = 2
0x0C: len (4) = 512 (0x200)
0x10: lsn_cycle (4) = 1
0x14: lsn_block (4) = 0
0x18: tail_lsn_cycle (4) = 1
0x1C: tail_lsn_block (4) = 0
0x20: crc (4) = 0
0x24: prev_block (4) = 0xFFFFFFFF
0x28: num_logops (4) = 1
0x2C: cycle_data[0] (4) = 0xB0C0D0D0
0x30-0x127: zeros
0x128: fmt (4) = 1
0x12C: uuid (16) = FS UUID
0x13C: size_in_blocks_maybe (4) = logblocks (as be32? needs verification)
```

Remaining log sectors: each 512-byte sector has first 4 bytes = cycle number (1),
rest zeroed. This is the "cycle stamping" that XFS uses for log wraparound detection.

Actually, for simplicity: just zero the entire log area. If the kernel rejects it,
we'll add the FEEDBABE header. The kernel's xlog_find_zeroed() handles this case.

## CRC Calculation
```c
// XFS CRC: CRC32C with seed ~0, no final complement, stored as native uint32_t
// (which is __le32 on x86)
static uint32_t xfs_calc_crc(void *buf, size_t len, size_t crc_offset)
{
    uint32_t *crc_field = (uint32_t *)((uint8_t *)buf + crc_offset);
    *crc_field = 0;
    *crc_field = crc32c(~0U, buf, len);
    return *crc_field;
}
```

## UUID Generation
Read 16 bytes from /dev/urandom, set version 4 bits:
```
uuid[6] = (uuid[6] & 0x0F) | 0x40;  // version 4
uuid[8] = (uuid[8] & 0x3F) | 0x80;  // variant 1
```

## Implementation Steps

1. Add big-endian write helpers: put_be16(), put_be32(), put_be64()
2. Add xfs_calc_crc() helper
3. Add xfs_gen_uuid() helper
4. Add geometry calculation: xfs_calc_geometry()
5. Write format_xfs_native() main function
6. Update main() to call format_xfs_native() instead of system("mkfs.xfs")
7. Remove the read_xfs_uuid() function (UUID is now generated internally)
8. Version bump to 1.4.0
9. Test: format loop device, mount with kernel XFS, verify ls/df/touch work

## fdblocks Calculation
fdblocks = sum of all AG freeblks
For each AG: freeblks = agblocks - used_blocks
- AG 0: used = 4 (hdr+btree) + 4 (AGFL) + 8 (inodes) = 16
- Log AG: used = 4 (hdr+btree) + logblocks + 4 (AGFL)
- Other AGs: used = 4 (hdr+btree) + 4 (AGFL) = 8
- Last AG may have fewer agblocks

## sb_logsunit
From reference: sb_logsunit = 1 (at offset 0xC4 in superblock). This is the
log stripe unit in bytes. 1 means "use basic sector writes" (no stripe alignment).

## Timestamp Format
XFS legacy timestamps (no BIGTIME):
```
struct xfs_legacy_timestamp {
    __be32 t_sec;   // seconds since epoch
    __be32 t_nsec;  // nanoseconds
};
```
Use current time from time(NULL) for sec, 0 for nsec.

# chk_mxfs -- MXFS Filesystem Validation Tool

## Overview

`chk_mxfs` is a standalone validation and repair tool for MXFS-formatted block devices. Checks integrity of all on-disk structures and can repair CRC mismatches, counter inconsistencies, and dirty journal slots.

## Version History

- **0.11.5** (2026-07-18): MEPOCH decode (NET2 §7.C membership plane).
  Each HB slot's 44-byte membership-epoch record at offset 456 (after
  the 40-byte header + 416-byte evict ring) is decoded when its own
  magic "MEPO" is present: epoch, member/fenced masks, voters, flags,
  self_incarnation.  Self-validating via crc32c over bytes 0..39
  (kernel `crc32c()` raw semantics — a private table implementation
  keeps the tool standalone); a bad CRC on a magic-matching record is
  an error.  PREPARED-flag records (staged single-decree candidates)
  are printed and labeled but never counted as committed authority;
  epoch-0 records are incarnation-bump carriers and are skipped too.
  Summary line reports the max committed epoch, its member mask and
  the record count; verbose prints every record.
- **0.9.13** (2026-03-11): Structural btree repair for damaged AGs. Inobt/finobt root reset: when all records are garbage (count=0) and AGI confirms no inodes, rewrites root as empty leaf. BNO/CNT btree rebuild: when btree blocks contain wrong magic (e.g., XFSB copies) and AG has no inodes, writes fresh single-extent leaves at standard positions (blocks 1,2), updates AGF roots/levels/freeblks/longest. Counting fix: validate_inobt_leaf skips totals accumulation for count=0 garbage records (prevents ifree > icount underflow). Superblock fdblocks repair now triggers on BNO btree sum mismatch.
- **0.9.12** (2026-03-11): Comprehensive CRC repair for all 8 structure types (MXFS super, journal super, journal slots, XFS superblock, AGF, AGI, btree blocks, inodes). Counter repairs for AGI icount/freecount from inobt, AGF freeblks from BNO btree, XFS SB icount/ifree/fdblocks from AG sums. Bug 123 fix: XFS SB counter repair used wrong CRC offset (0xC0 instead of 0xE0). Version derived from mxfs_common.h MXFS_VERSION macros.
- **0.6.2** (2026-03-10): Deep validation: free space btree (BNO/CNT) walk with record ordering, inode btree (inobt/finobt) walk with freecount/bitmask verification, inode spot-check (magic/CRC/format/mode/nlink), cross-check totals against superblock counters, per-AG summary report.
- **0.6.0** (2026-03-06): Initial implementation. Validates MXFS super, journal, disklock, and XFS structures with CRC32C verification.

## Architecture

Single-file C program (`chk_mxfs.c`), no libmxfs linkage. Uses POSIX `pread()` and `pwrite()` for all I/O. Includes a software CRC32C implementation (Castagnoli polynomial 0x82F63B78) and big-endian read/write helpers for XFS on-disk fields.

### Validation Stages

1. **MXFS On-Disk Super** (first 4KB at offset 0)
   - Magic (0x5346584D), version (1), CRC32C
   - Region offset/size bounds within device_size
   - Region non-overlapping (super, journal, disklock, xfs_data)

2. **Journal Region** (at journal_offset)
   - Journal super (512B): magic (0x4D584A4C), version, CRC32C
   - Per-slot headers: magic, CRC32C, dirty/clean status, owner node

3. **Disklock Region** (at disklock_offset)
   - Heartbeat slots (64 x 512B): magic (0x4D584C4B), active flag
   - MEPOCH record per slot (offset 456, 44B): magic "MEPO", crc32c,
     committed-epoch summary (PREPARED/epoch-0 records excluded)
   - Reports active vs empty slot counts

4. **XFS Structures** (at xfs_data_offset)
   - Superblock (sector 0): magic (0x58465342), CRC32C at offset 0xE0
   - Per-AG AGF: magic, seqno, CRC32C at offset 0xD8
   - Per-AG AGI: magic, seqno, CRC32C at offset 0x138
   - Extracts geometry: blocksize, agcount, agblocks, inodesize, inopblock, features

5. **Free Space BTree Validation** (per AG)
   - **BNO btree**: Reads root from AGF (offset 0x10). Validates V5 CRC magic (0x41423342 "AB3B"), CRC at offset 0x34, level, numrecs. For leaf blocks: validates records sorted by startblock ascending. For multi-level trees: recursively walks internal nodes to leaves.
   - **CNT btree**: Reads root from AGF (offset 0x14). Validates V5 CRC magic (0x41423343 "AB3C"), same header checks. For leaf blocks: validates records sorted by blockcount ascending (then startblock for ties).
   - **Cross-checks**: BNO total == CNT total; BNO total == AGF freeblks.

6. **Inode BTree Validation** (per AG)
   - **inobt**: Reads root from AGI (offset 0x14). Validates V5 CRC magic (0x49414233 "IAB3"), header checks. Each leaf record (16 bytes): startino alignment to 64, ordering, count in [1..64], freecount <= count, popcount(free_mask) matches freecount (with sparse hole handling).
   - **finobt** (if feature flag set): Reads root from AGI (offset 0x148). Validates V5 CRC magic (0x46494233 "FIB3"), same record validation.
   - **Cross-checks**: inobt total == AGI count; inobt free == AGI freecount; finobt free == inobt free.

7. **Inode Spot-Check**
   - Root directory inode: validates V3 dinode magic (0x494E "IN"), CRC at offset 0x64, version==3, format in [0..3], file type bits present in mode, nlink>0, di_ino self-reference.
   - rbmino and rsumino (rootino+1, rootino+2): same validation.
   - Up to 8 additional allocated inodes found by walking AG 0 inobt leaf records.

8. **Summary Report**
   - Per-AG free block counts (AGF vs btree-verified)
   - Total free blocks: BNO btree sum vs AGF sum vs superblock fdblocks
   - Total inodes: inobt sum vs superblock icount
   - Total free inodes: inobt sum vs superblock ifree
   - Allocated inode count

### BTree Walk Algorithm

Both free space and inode btree validation use recursive descent:
- Read block at AG-relative block number
- Validate V5 short-form header: magic, CRC (at offset 0x34 over full blocksize), level matches expected
- **Leaf (level 0)**: validate individual records (ordering, bounds, internal consistency)
- **Internal (level > 0)**: keys at offset 0x38, pointers after keys. Recurse into each child pointer.
- Maximum depth: 16 levels (safety bound)

### CRC Conventions

- **MXFS/Journal structures**: Native byte order. CRC32C with seed `~0U`, stored directly (no complement).
- **XFS structures**: Big-endian fields. CRC32C with seed `~0U`, final complement `~crc`, stored as native uint32_t (le32 on x86).

### Key CRC Offsets

| Structure | CRC Offset | Notes |
|-----------|-----------|-------|
| MXFS super | field `crc` in struct | Native, no complement |
| Journal super | offset 20 | Native, no complement |
| Journal slot hdr | offset 20 | Native, no complement |
| XFS superblock | 0xE0 (224) | Native uint32_t, complemented |
| XFS AGF | 0xD8 (216) | Native uint32_t, complemented |
| XFS AGI | 0x138 (312) | Native uint32_t, complemented |
| V5 btree sblock | 0x34 (52) | Native uint32_t, complemented |
| V3 dinode | 0x64 (100) | Native uint32_t, complemented |

### XFS On-Disk Field Offsets Used

**Superblock (sector 0):**
| Offset | Size | Field |
|--------|------|-------|
| 0x00 | 4 | sb_magic |
| 0x04 | 4 | sb_blocksize |
| 0x08 | 8 | sb_dblocks |
| 0x20 | 16 | sb_uuid |
| 0x38 | 8 | sb_rootino |
| 0x54 | 4 | sb_agblocks |
| 0x58 | 4 | sb_agcount |
| 0x66 | 2 | sb_sectsize |
| 0x68 | 2 | sb_inodesize |
| 0x6A | 2 | sb_inopblock |
| 0x7B | 1 | sb_inopblog |
| 0x7C | 1 | sb_agblklog |
| 0x80 | 8 | sb_icount |
| 0x88 | 8 | sb_ifree |
| 0x90 | 8 | sb_fdblocks |
| 0xD4 | 4 | sb_features_ro_compat |
| 0xE0 | 4 | sb_crc |

**AGF (sector 1):**
| Offset | Size | Field |
|--------|------|-------|
| 0x0C | 4 | agf_length |
| 0x10 | 4 | agf_roots[0] (bnobt) |
| 0x14 | 4 | agf_roots[1] (cntbt) |
| 0x1C | 4 | agf_levels[0] (bnobt) |
| 0x20 | 4 | agf_levels[1] (cntbt) |
| 0x34 | 4 | agf_freeblks |
| 0x38 | 4 | agf_longest |

**AGI (sector 2):**
| Offset | Size | Field |
|--------|------|-------|
| 0x0C | 4 | agi_length |
| 0x10 | 4 | agi_count |
| 0x14 | 4 | agi_root (inobt) |
| 0x18 | 4 | agi_level (inobt) |
| 0x1C | 4 | agi_freecount |
| 0x148 | 4 | agi_free_root (finobt) |
| 0x14C | 4 | agi_free_level (finobt) |

**V5 short-form btree block header (56 bytes):**
| Offset | Size | Field |
|--------|------|-------|
| 0x00 | 4 | bb_magic |
| 0x04 | 2 | bb_level |
| 0x06 | 2 | bb_numrecs |
| 0x08 | 4 | bb_leftsib |
| 0x0C | 4 | bb_rightsib |
| 0x10 | 8 | bb_blkno |
| 0x18 | 8 | bb_lsn |
| 0x20 | 16 | bb_uuid |
| 0x30 | 4 | bb_owner |
| 0x34 | 4 | bb_crc |
| 0x38 | - | records start |

**Inobt record (16 bytes):**
| Offset | Size | Field |
|--------|------|-------|
| 0 | 4 | ir_startino |
| 4 | 2 | ir_holemask |
| 6 | 1 | ir_count |
| 7 | 1 | ir_freecount |
| 8 | 8 | ir_free (bitmask) |

**V3 dinode:**
| Offset | Size | Field |
|--------|------|-------|
| 0x00 | 2 | di_magic (0x494E) |
| 0x02 | 2 | di_mode |
| 0x04 | 1 | di_version |
| 0x05 | 1 | di_format |
| 0x10 | 4 | di_nlink |
| 0x64 | 4 | di_crc |
| 0x98 | 8 | di_ino |

## Build

```
cc -Wall -Wextra -O2 -I../include -o chk_mxfs chk_mxfs.c
```

## Usage

```
chk_mxfs [-v] [-a|-p|-y|-n] /dev/sdX
```

- `-v`: Verbose output (detailed info for each check: btree records, inode fields, per-AG geometry)
- `-n`: Check only, no modifications (default for chk_mxfs)
- `-a`: Auto-repair safe fixes (default for fsck.mxfs)
- `-p`: Same as -a (preen mode, used by boot scripts)
- `-y`: Repair all, answer yes to everything
- Returns 0 if clean, 1 if errors corrected, 4 if errors remain

### Repair Capabilities

**CRC repairs** (recompute from valid data, write back):
- MXFS super CRC (native, no complement, 4KB at offset 0)
- Journal super CRC (native, 512B at journal_offset)
- Journal slot CRC (native, 512B per slot)
- XFS superblock CRC (complemented, 512B at xfs_data_offset, offset 0xE0)
- AGF CRC (complemented, 512B per AG, offset 0xD8)
- AGI CRC (complemented, 512B per AG, offset 0x138)
- Btree block CRC (complemented, blocksize, offset 0x34)
- Inode CRC (complemented, inodesize, offset 0x64)

CRC repairs are only attempted when the structure magic is valid (data intact, only checksum wrong). Structurally damaged blocks are not repaired.

**Counter repairs** (fix header from btree scan):
- AGF freeblks from BNO/CNT btree consensus
- AGI icount/freecount from inobt walk
- XFS superblock icount/ifree/fdblocks from AG sums

**Structural btree repairs** (rebuild damaged btrees for empty AGs):
- Inobt/finobt root reset: when all records are garbage (count=0) and AGI confirms 0 allocated inodes, rewrites root as empty V5 leaf (magic, uuid, owner, CRC). Fixes AGI level if tree was multi-level.
- BNO/CNT btree rebuild: when btree blocks have wrong magic (e.g., XFSB backup superblock copies) and AG has 0 allocated inodes, writes fresh single-extent leaves at standard positions (block 1=BNO, block 2=CNT) with free space [startblock=8, blockcount=agf_length-8]. Updates AGF bno_root, cnt_root, levels, freeblks, longest.
- Only triggers for AGs with no allocated inodes — no risk of data loss.

**Journal repairs**:
- Dirty journal slot cleared to clean (post-crash cleanup)

### Example Output (non-verbose)

```
chk_mxfs v0.6.2 -- checking /dev/sdb
MXFS super .............. OK  (version=1, device=20.00 GB)
Journal ................. OK  (64 slots, 64 clean, 0 dirty)
Disklock ................ OK  (64 HB slots, 0 active)
XFS superblock .......... OK  (blocksize=4096, agcount=19, fdblocks=4982748)
  UUID: 3a0368c6-499a-48b2-81e2-e4e170e4f010
  AG 0: AGF OK, AGI OK
  AG 0 BNO/CNT btrees .. OK  (free=262504 blocks)
  AG 0 inobt ........... OK  (64 inodes, 61 free, 1 records)
  AG 1: AGF OK, AGI OK
  AG 1 BNO/CNT btrees .. OK  (free=262512 blocks)
  AG 1 inobt ........... OK  (0 inodes, 0 free, 0 records)
  ...
Inode spot-check ........ OK  (3/3 inodes passed)

--- Summary ---
  Per-AG free blocks:
    AG 0: 262504 blocks (btree verified: 262504)
    AG 1: 262512 blocks (btree verified: 262512)
    ...
  Total free blocks (BNO btree sum): 4982748
  Total free blocks (AGF sum):       4982748
  Superblock fdblocks:               4983824
  Total inodes (inobt sum):          64
  Superblock icount:                 64
  Total free inodes (inobt sum):     61
  Superblock ifree:                  61
  Allocated inodes:                  3

chk_mxfs: filesystem clean, 0 errors
```

## Dependencies

- `<mxfs/mxfs_super.h>` for the on-disk super struct
- `<mxfs/mxfs_common.h>` for MXFS_VERSION_MAJOR/MINOR/PATCH
- Linux `<linux/fs.h>` for BLKGETSIZE64
- No runtime dependencies beyond libc

## Notes on Cross-Check: fdblocks vs BNO sum

The XFS superblock `sb_fdblocks` includes AGFL blocks (typically 4 per AG) that are not counted in `agf_freeblks`. So `sb_fdblocks >= sum(agf_freeblks)` is expected. The tool reports both values for comparison but only flags an error if the AGF sum exceeds fdblocks (which would indicate corruption).

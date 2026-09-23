#!/usr/bin/env python3
"""xfs_block_patch.py — set one big-endian field in one on-disk XFS block of an
MXFS image and refresh the block's XFS CRC, so an offline checker sees a
SEMANTIC inconsistency and not merely a checksum failure.

    xfs_block_patch.py IMAGE BLOCK_OFF BLOCK_LEN CRC_OFF FIELD_OFF WIDTH VALUE

BLOCK_OFF   byte offset of the block in the image (the envelope's
            xfs_data_offset plus the XFS address)
BLOCK_LEN   bytes covered by the CRC (the sector for sb/AGF/AGI, the
            filesystem block for a btree block)
CRC_OFF     byte offset of the CRC inside the block, or -1 for none
FIELD_OFF   byte offset of the field inside the block
WIDTH       1, 2, 4 or 8 (big-endian; the on-disk XFS byte order)
VALUE       the new value; a leading +/- makes it relative to the current one

The CRC is the XFS one: crc32c (Castagnoli, table 0x82F63B78) over the
block with the CRC field zeroed, seeded ~0, complemented, stored native
(little-endian) — the same computation tools/chk_mxfs.c verifies against.
Prints `PATCHED off=<block> field=<field> width=<w> old=<v> new=<v>
crc_off=<c>` on success; exit 2 on a usage error, 1 on an I/O error.

Used by tests/chk_oracle_calibration.sh to build the corrupted fixtures the
checker must FAIL.  Never point it at a mounted filesystem or the shared LUN.
"""
import os
import struct
import sys

TABLE = []
for i in range(256):
    c = i
    for _ in range(8):
        c = (c >> 1) ^ 0x82F63B78 if c & 1 else c >> 1
    TABLE.append(c)


def crc32c(data, crc=0xFFFFFFFF):
    for b in data:
        crc = (crc >> 8) ^ TABLE[(crc ^ b) & 0xFF]
    return crc


def main(argv):
    if len(argv) != 8:
        sys.stderr.write(__doc__)
        return 2
    image = argv[1]
    block_off, block_len, crc_off, field_off, width = (int(argv[2], 0),
                                                       int(argv[3], 0),
                                                       int(argv[4], 0),
                                                       int(argv[5], 0),
                                                       int(argv[6], 0))
    fmt = {1: ">B", 2: ">H", 4: ">I", 8: ">Q"}.get(width)
    if fmt is None or field_off + width > block_len:
        sys.stderr.write("bad width or field outside the block\n")
        return 2
    fd = os.open(image, os.O_RDWR)
    try:
        blk = bytearray(os.pread(fd, block_len, block_off))
        if len(blk) != block_len:
            sys.stderr.write("short read at %d\n" % block_off)
            return 1
        old = struct.unpack_from(fmt, blk, field_off)[0]
        v = argv[7]
        new = old + int(v, 0) if v[0] in "+-" else int(v, 0)
        new &= (1 << (8 * width)) - 1
        struct.pack_into(fmt, blk, field_off, new)
        if crc_off >= 0:
            struct.pack_into("<I", blk, crc_off, 0)
            struct.pack_into("<I", blk, crc_off, (~crc32c(bytes(blk))) & 0xFFFFFFFF)
        if os.pwrite(fd, bytes(blk), block_off) != block_len:
            sys.stderr.write("short write at %d\n" % block_off)
            return 1
        os.fsync(fd)
    finally:
        os.close(fd)
    print("PATCHED off=%d field=%d width=%d old=%d new=%d crc_off=%d"
          % (block_off, field_off, width, old, new, crc_off))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

#!/usr/bin/env python3
"""dinode_inject.py — read or rewrite ONE on-disk dinode of an MXFS volume,
resealing the v5 dinode crc so the image reads as a valid (not corrupt)
dinode.

D-0351 containment instrument (sess430): plant a LIVE dinode image under an
inode number the inobt says is FREE — exactly the state a crossed FREE-PUBLISH
invariant leaves behind — so the allocator's two-phase candidate validation
(P-DIALLOC-DISKLIVE, quarantine, clean re-pick) can be measured against the
pre-containment behaviour (P-CR62 DISK-LIVE -> dirty xfs_trans_cancel ->
node shutdown).

Geometry: the XFS region starts at <xfs_off> (chk_mxfs -v prints
`xfs_data_offset=`); the sb there gives blocksize (+4), agblocks (+84),
inodesize (+104), inopblog (+123), agblklog (+124).  Dinode home of `ino`:
  agno  = ino >> (agblklog + inopblog)
  agino = ino & ((1 << (agblklog + inopblog)) - 1)
  agbno = agino >> inopblog ; slot = agino & (inopblock - 1)
  byte  = xfs_off + (agno * agblocks + agbno) * blocksize + slot * inodesize
v5 dinode: magic 'IN' +0, di_mode be16 +2, di_gen be32 +0x5c, di_crc le32
+0x64 = ~crc32c(~0, image with di_crc zeroed).

Usage:
  dinode_inject.py <dev> <xfs_off> <ino> show
  dinode_inject.py <dev> <xfs_off> <ino> setlive <gen>   (mode 0100644, nlink 1)
  dinode_inject.py <dev> <xfs_off> <ino> setfree         (mode 0, nlink 0)
Writes go through O_DIRECT (sector-aligned, one inodesize-multiple block).
Exit 0 on success, 2 on a slot without 'IN' magic (show still prints).
"""
import mmap
import os
import struct
import sys

_tbl = []
for i in range(256):
    c = i
    for _ in range(8):
        c = (c >> 1) ^ 0x82F63B78 if c & 1 else c >> 1
    _tbl.append(c)


def crc32c(crc, data):
    for b in data:
        crc = _tbl[(crc ^ b) & 0xFF] ^ (crc >> 8)
    return crc & 0xFFFFFFFF


def dinode_crc(img):
    tmp = bytearray(img)
    tmp[0x64:0x68] = b"\0\0\0\0"
    return (~crc32c(0xFFFFFFFF, bytes(tmp))) & 0xFFFFFFFF


def main():
    if len(sys.argv) < 5:
        print(__doc__)
        return 2
    dev, xfs_off, ino, op = sys.argv[1], int(sys.argv[2], 0), int(sys.argv[3], 0), sys.argv[4]
    fd = os.open(dev, os.O_RDONLY)
    sb = os.pread(fd, 512, xfs_off)
    os.close(fd)
    if sb[:4] != b"XFSB":
        print("ERROR: no XFSB magic at xfs_off", xfs_off)
        return 2
    blocksize = struct.unpack(">I", sb[4:8])[0]
    agblocks = struct.unpack(">I", sb[84:88])[0]
    inodesize = struct.unpack(">H", sb[104:106])[0]
    inopblock = struct.unpack(">H", sb[106:108])[0]
    inopblog = sb[123]
    agblklog = sb[124]
    agno = ino >> (agblklog + inopblog)
    agino = ino & ((1 << (agblklog + inopblog)) - 1)
    agbno = agino >> inopblog
    slot = agino & (inopblock - 1)
    byte = xfs_off + (agno * agblocks + agbno) * blocksize + slot * inodesize
    print("geometry blocksize=%d agblocks=%d inodesize=%d inopblock=%d agblklog=%d inopblog=%d" %
          (blocksize, agblocks, inodesize, inopblock, agblklog, inopblog))
    print("ino=%d agno=%d agino=%d agbno=%d slot=%d byte=%d lba=%d" %
          (ino, agno, agino, agbno, slot, byte, byte // 512))
    # O_DIRECT: read/write the whole inode (inodesize is a sector multiple)
    fd = os.open(dev, os.O_RDWR | os.O_DIRECT)
    buf = mmap.mmap(-1, inodesize)
    os.preadv(fd, [buf], byte)
    img = bytearray(buf[:inodesize])

    def show(tag, im):
        magic = im[0:2]
        mode = struct.unpack(">H", im[2:4])[0]
        nlink = struct.unpack(">I", im[0x10:0x14])[0]
        gen = struct.unpack(">I", im[0x5c:0x60])[0]
        crc = struct.unpack("<I", im[0x64:0x68])[0]
        ok = magic == b"IN" and crc == dinode_crc(im)
        print("%s magic=%s mode=0%o nlink=%d gen=%u crc=0x%08x crc_ok=%d" %
              (tag, magic.hex(), mode, nlink, gen, crc, 1 if ok else 0))
        return magic == b"IN"

    valid = show("before", img)
    if op == "show":
        os.close(fd)
        return 0 if valid else 2
    if not valid:
        print("ERROR: slot has no IN magic; refusing to write")
        os.close(fd)
        return 2
    if op == "setlive":
        gen = int(sys.argv[5], 0)
        img[2:4] = struct.pack(">H", 0o100644)
        img[0x10:0x14] = struct.pack(">I", 1)
        img[0x5c:0x60] = struct.pack(">I", gen & 0xFFFFFFFF)
    elif op == "setfree":
        img[2:4] = b"\0\0"
        img[0x10:0x14] = b"\0\0\0\0"
    else:
        print("ERROR: unknown op", op)
        os.close(fd)
        return 2
    img[0x64:0x68] = struct.pack("<I", dinode_crc(img))
    buf[:inodesize] = bytes(img)
    os.pwritev(fd, [buf], byte)
    os.fsync(fd)
    os.preadv(fd, [buf], byte)
    show("after", bytearray(buf[:inodesize]))
    os.close(fd)
    return 0


if __name__ == "__main__":
    sys.exit(main())

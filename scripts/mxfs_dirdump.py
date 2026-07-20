#!/usr/bin/env python3
"""mxfs_dirdump.py — decode an mxfs (XFS-v5-in-envelope) directory's on-disk
data + leaf structures straight from the shared LUN, no kernel involved.

sess4 (ccloop a16ec5f2): built to autopsy the dir_reuse "readdir sees the
name, lookup ENOENTs" class — a dirent present in a dir DATA block whose
hashval is absent from the LEAF index.

Usage:
  sudo python3 scripts/mxfs_dirdump.py /dev/mxfs-shared <dir-ino> [name ...]

For each name: prints the dirent (data daddr, offset, inum, hash) and
whether/where its hash appears in the leaf index (leaf daddr, ent idx,
address -> does it point back at the dirent).  With no names: dumps a
summary of every data + leaf block.
"""
import struct, sys

SECT = 512


def be(b, off, n):
    return int.from_bytes(b[off:off + n], 'big')


def xfs_hash(name: bytes) -> int:
    h = 0
    for c in name:
        h = (c ^ ((h << 7 | h >> 25) & 0xffffffff)) & 0xffffffff
    return h


class Img:
    def __init__(self, path):
        self.f = open(path, 'rb')
        # mxfs envelope: locate xfs_data_offset from the MXFS super.
        # Layout (tools/mkfs_mxfs): magic "MXFS" at 0, version, then
        # journal/disklock/xfs_data offsets.  Rather than trust field
        # offsets, scan the first 4KB for the "XFSB"-bearing sector by
        # reading the mxfs super's u64 at 0x18..0x40 candidates, falling
        # back to a bounded scan for the XFSB magic.
        head = self.rd(0, 4096)
        self.xfs_base = None
        if head[:4] == b'MXFS':
            for off in range(8, 0x60, 8):
                cand = be(head, off, 8)
                if 4096 <= cand < 1 << 40 and cand % SECT == 0:
                    try:
                        if self.rd(cand, 4)[:4] == b'XFSB':
                            self.xfs_base = cand
                            break
                    except Exception:
                        pass
        if self.xfs_base is None:
            # bounded scan: every 512B up to 512MB
            for cand in range(0, 512 << 20, SECT):
                if self.rd(cand, 4)[:4] == b'XFSB':
                    self.xfs_base = cand
                    break
        if self.xfs_base is None:
            raise SystemExit('no XFSB found — not an mxfs/XFS device?')
        sb = self.rd(self.xfs_base, 512)
        self.blocksize = be(sb, 0x04, 4)
        self.agblocks = be(sb, 0x54, 4)
        self.agcount = be(sb, 0x58, 4)
        self.inodesize = be(sb, 0x68, 2)
        self.inopblock = be(sb, 0x6a, 2)
        self.blocklog = sb[0x78]
        self.inopblog = sb[0x7b]
        self.agblklog = sb[0x7c]
        self.dirblklog = sb[0xc0]
        self.dirblksize = self.blocksize << self.dirblklog
        self.blkbb = self.blocksize // SECT

    def rd(self, byteoff, n):
        self.f.seek(byteoff)
        return self.f.read(n)

    def daddr_bytes(self, daddr):
        return self.xfs_base + daddr * SECT

    def fsb_to_daddr(self, fsbno):
        agno = fsbno >> self.agblklog
        agbno = fsbno & ((1 << self.agblklog) - 1)
        return (agno * self.agblocks + agbno) * self.blkbb

    def ino_daddr_off(self, ino):
        agino_log = self.agblklog + self.inopblog
        agno = ino >> agino_log
        agino = ino & ((1 << agino_log) - 1)
        agbno = agino >> self.inopblog
        idx = agino & (self.inopblock - 1)
        daddr = (agno * self.agblocks + agbno) * self.blkbb
        return daddr, idx * self.inodesize

    def read_dinode(self, ino):
        daddr, off = self.ino_daddr_off(ino)
        raw = self.rd(self.daddr_bytes(daddr) + off, self.inodesize)
        if raw[:2] != b'IN':
            raise SystemExit('ino %d: bad dinode magic %r at daddr %d off %d'
                             % (ino, raw[:2], daddr, off))
        return raw

    def extents(self, dinode):
        version = dinode[4]
        fmt = dinode[5]
        if fmt != 2:
            raise SystemExit('dir data fork fmt=%d (not EXTENTS) — extend me'
                             % fmt)
        nex = be(dinode, 0x4c, 4)
        lit = 176 if version == 3 else 100
        out = []
        for i in range(nex):
            rec = dinode[lit + 16 * i: lit + 16 * i + 16]
            v = int.from_bytes(rec, 'big')
            blockcount = v & ((1 << 21) - 1)
            startblock = (v >> 21) & ((1 << 52) - 1)
            startoff = (v >> 73) & ((1 << 54) - 1)
            out.append((startoff, startblock, blockcount))
        return out


def walk_data_block(img, blk, daddr):
    """Yield (name, inum, tag_off, hash) for live entries; also stale count."""
    magic = blk[:4]
    is_block = magic == b'XDB3'
    if magic not in (b'XDD3', b'XDB3'):
        return None, magic
    p = 64  # sizeof(xfs_dir3_data_hdr)
    end = len(blk)
    if is_block:
        lcount = be(blk, len(blk) - 8, 4)
        end = len(blk) - 8 - lcount * 8
    ents = []
    while p + 6 <= end:
        freetag = be(blk, p, 2)
        if freetag == 0xffff:
            ln = be(blk, p + 2, 2)
            if ln < 8:
                break
            p += ln
            continue
        inum = be(blk, p, 8)
        nl = blk[p + 8]
        if nl == 0:
            break
        name = blk[p + 9:p + 9 + nl]
        entsize = (9 + nl + 2 + 7) & ~7  # +ftype(1)? v5 has ftype
        entsize = (9 + nl + 1 + 2 + 7) & ~7
        ents.append((name, inum, p, xfs_hash(name)))
        p += entsize
    return ents, magic


def walk_leaf(img, blk):
    magic4 = blk[:4]
    info_magic = be(blk, 8, 2)
    # xfs_da3_blkinfo: forw(4) back(4) magic(2) pad(2) crc(4) blkno(8) lsn(8) uuid(16) owner(8)
    # xfs_da3_blkinfo is 56 bytes: forw(4) back(4) magic(2) pad(2) crc(4)
    # blkno(8) lsn(8) uuid(16) owner(8).  leaf3/node3 hdr: count@0x38,
    # stale-or-level@0x3a, pad(4) -> entries at 0x40.
    if info_magic in (0x3df1, 0x3dff):     # LEAF1 / LEAFN (dir3)
        count = be(blk, 0x38, 2)
        stale = be(blk, 0x3a, 2)
        ents = []
        for i in range(count):
            h = be(blk, 0x40 + 8 * i, 4)
            addr = be(blk, 0x40 + 8 * i + 4, 4)
            ents.append((h, addr))
        return 'leaf', count, stale, ents
    if info_magic == 0x3ebe:               # DA3 NODE
        count = be(blk, 0x38, 2)
        level = be(blk, 0x3a, 2)
        ents = []
        for i in range(count):
            h = be(blk, 0x40 + 8 * i, 4)
            before = be(blk, 0x40 + 8 * i + 4, 4)
            ents.append((h, before))
        return 'node', count, level, ents
    return ('?%04x' % info_magic), 0, 0, []


def main():
    dev, ino = sys.argv[1], int(sys.argv[2])
    names = [n.encode() for n in sys.argv[3:]]
    img = Img(dev)
    print('xfs_base=%d blocksize=%d dirblksize=%d agblocks=%d inodesize=%d' %
          (img.xfs_base, img.blocksize, img.dirblksize, img.agblocks,
           img.inodesize))
    di = img.read_dinode(ino)
    exts = img.extents(di)
    dbb = img.dirblksize // SECT
    leafoff_fsb = (32 << 30) // img.blocksize
    freeoff_fsb = (64 << 30) // img.blocksize
    want = {n: xfs_hash(n) for n in names}
    for n, h in want.items():
        print('want %-20s hash=0x%08x' % (n.decode(), h))
    found_dirents = {}
    leaf_hits = {}
    for (fo, sb_, bc) in exts:
        for j in range(0, bc, 1 << img.dirblklog):
            fileoff = fo + j
            daddr = img.fsb_to_daddr(sb_ + j)
            blk = img.rd(img.daddr_bytes(daddr), img.dirblksize)
            if fileoff < leafoff_fsb:
                ents, magic = walk_data_block(img, blk, daddr)
                if ents is None:
                    print('data daddr=%d BAD MAGIC %r' % (daddr, magic))
                    continue
                live = len(ents)
                if not names:
                    print('data daddr=%d magic=%s live=%d' %
                          (daddr, blk[:4].decode(), live))
                for (name, inum, off, h) in ents:
                    if name in want:
                        found_dirents[name] = (daddr, off, inum, h, fileoff)
            elif fileoff < freeoff_fsb:
                kind, count, x, ents = walk_leaf(img, blk)
                if not names:
                    print('%s daddr=%d count=%d stale/level=%d' %
                          (kind, daddr, count, x))
                for n, h in want.items():
                    for i, (eh, addr) in enumerate(ents):
                        if eh == h and kind == 'leaf':
                            leaf_hits.setdefault(n, []).append(
                                (daddr, i, addr, fileoff))
    print()
    for n in names:
        d = found_dirents.get(n)
        l = leaf_hits.get(n, [])
        print('== %s' % n.decode())
        if d:
            daddr, off, inum, h, fileoff = d
            # dir2 leaf address: (dir-space byte offset) >> 3
            want_addr = (fileoff // (1 << img.dirblklog) *
                         img.dirblksize + off) >> 3
            print('   dirent: data daddr=%d off=%d inum=%d fileoff_fsb=%d '
                  'expect_leaf_addr=0x%x' % (daddr, off, inum, fileoff,
                                             want_addr))
        else:
            print('   dirent: NOT FOUND in any data block')
        if l:
            for (daddr, i, addr, fileoff) in l:
                print('   leaf hit: leaf daddr=%d ent[%d] addr=0x%x' %
                      (daddr, i, addr))
        else:
            print('   leaf hit: NONE — hash absent from leaf index')


if __name__ == '__main__':
    main()

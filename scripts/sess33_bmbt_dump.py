#!/usr/bin/env python3
# sess33 (ccloop 14d31183) — parse an MXFS dir inode's on-disk BTREE bmbt and
# print every data-fork extent (startoff, startblock-fsb, daddr, blockcount).
# Usage: sess33_bmbt_dump.py <dev> <ino>
# Reads the MXFS envelope for xfs_data_offset, the XFS sb for geometry, the
# dinode for the bmdr root, then walks BMA3 child blocks to the leaves.
import struct, sys

dev = sys.argv[1]
ino = int(sys.argv[2])
f = open(dev, 'rb')

def rd(off, n):
    f.seek(off)
    return f.read(n)

# MXFS envelope super at byte 0
sup = rd(0, 4096)
magic, = struct.unpack_from('<I', sup, 0)
assert magic == 0x5346584D, hex(magic)
data_off, = struct.unpack_from('<Q', sup, 88)

# XFS sb
sb = rd(data_off, 512)
assert sb[0:4] == b'XFSB', sb[0:4]
blocksize, = struct.unpack_from('>I', sb, 4)
agblocks, = struct.unpack_from('>I', sb, 84)
agcount, = struct.unpack_from('>I', sb, 88)
inodesize, = struct.unpack_from('>H', sb, 104)
inopblock, = struct.unpack_from('>H', sb, 106)
blocklog = sb[120]
inodelog = sb[122]
inopblog = sb[123]
agblklog = sb[124]
print(f"# sb: blocksize={blocksize} agblocks={agblocks} agcount={agcount} "
      f"inodesize={inodesize} agblklog={agblklog}")

def fsb_to_daddr(fsb):
    agno = fsb >> agblklog
    agbno = fsb & ((1 << agblklog) - 1)
    return (agno * agblocks + agbno) * (blocksize // 512)

def ino_to_daddr_off(ino):
    agno = ino >> (agblklog + inopblog)
    agino = ino & ((1 << (agblklog + inopblog)) - 1)
    agbno = agino >> inopblog
    idx = agino & ((1 << inopblog) - 1)
    daddr = (agno * agblocks + agbno) * (blocksize // 512)
    return daddr, idx * inodesize

daddr, boff = ino_to_daddr_off(ino)
dino = rd(data_off + daddr * 512 + boff, inodesize)
assert dino[0:2] == b'IN', dino[0:2]
mode, = struct.unpack_from('>H', dino, 2)
version = dino[4]
fmt = dino[5]
size, = struct.unpack_from('>Q', dino, 56)
nblocks, = struct.unpack_from('>Q', dino, 72)
nextents, = struct.unpack_from('>I', dino, 76)
forkoff = dino[82]
core = 176 if version == 3 else 96
print(f"# dinode ino={ino} mode={oct(mode)} fmt={fmt} size={size} "
      f"nblocks={nblocks} nextents={nextents} forkoff={forkoff}")

def unpack_rec(l0, l1):
    startoff = (l0 >> 9) & ((1 << 54) - 1)
    startblock = ((l0 & 0x1ff) << 43) | (l1 >> 21)
    count = l1 & 0x1fffff
    return startoff, startblock, count

extents = []
if fmt == 2:  # EXTENTS: packed recs inline in fork
    pos = core
    for i in range(nextents):
        l0, l1 = struct.unpack_from('>QQ', dino, pos + 16 * i)
        extents.append(unpack_rec(l0, l1))
elif fmt == 3:  # BTREE: bmdr root inline
    dfork_size = (forkoff * 8) if forkoff else (inodesize - core)
    level, nrec = struct.unpack_from('>HH', dino, core)
    # bmdr: keys at core+4, ptrs in second half of the root area
    maxrec = (dfork_size - 4) // 16
    ptr0 = core + 4 + maxrec * 8
    ptrs = [struct.unpack_from('>Q', dino, ptr0 + 8 * i)[0]
            for i in range(nrec)]
    print(f"# bmdr root: level={level} nrec={nrec} dfork_size={dfork_size}")
    stack = [(p, level) for p in ptrs]
    while stack:
        fsb, lvl = stack.pop(0)
        blk = rd(data_off + fsb_to_daddr(fsb) * 512, blocksize)
        bmag = blk[0:4]
        blevel, bnrec = struct.unpack_from('>HH', blk, 4)
        if bmag not in (b'BMA3', b'BMAP'):
            print(f"# BAD child fsb={fsb} daddr={fsb_to_daddr(fsb)} "
                  f"magic={bmag}")
            continue
        hdr = 72 if bmag == b'BMA3' else 24  # v5 long-form header
        if blevel == 0:
            for i in range(bnrec):
                l0, l1 = struct.unpack_from('>QQ', blk, hdr + 16 * i)
                extents.append(unpack_rec(l0, l1))
        else:
            maxr = (blocksize - hdr) // 16
            p0 = hdr + maxr * 8
            for i in range(bnrec):
                p, = struct.unpack_from('>Q', blk, p0 + 8 * i)
                stack.append((p, blevel))
else:
    print(f"# fmt={fmt} not handled")

extents.sort()
tot = 0
for so, sb_, cnt in extents:
    print(f"EXT startoff={so} fsb={sb_} daddr={fsb_to_daddr(sb_)} count={cnt}")
    tot += cnt
print(f"# total extents={len(extents)} blocks={tot}")

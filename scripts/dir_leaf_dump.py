#!/usr/bin/env python3
# dir_leaf_dump.py — raw forensic dump of an MXFS directory inode's extent map
# and its dir2 LEAF block(s), straight off the shared block device (no XFS
# tooling — the MXFS envelope offsets are honored).
#
# Reads the MXFS envelope super (sector 0) for xfs_data_offset, the XFS sb for
# geometry, the target dinode (extents format only), then dumps every extent
# and decodes any leaf block found at/after XFS_DIR2_LEAF_OFFSET:
#   - leaf hdr magic/count/stale
#   - every leaf entry (hashval, address, stale?)
#   - SORT-ORDER violations (hashval must be ascending) — the smoking gun for
#     the dir_reuse "one name becomes un-unlinkable" face (binary-search
#     visibility then depends on surrounding entries).
#   - if a NAME is given: its xfs_da_hashname hash + whether/where present.
#
# Usage: dir_leaf_dump.py <blockdev> <inode#> [name-to-hash ...]
# Safe: read-only.  Run on any node (device coherent via shared target cache).
import struct, sys, uuid

def be32(b, o): return struct.unpack_from('>I', b, o)[0]
def be16(b, o): return struct.unpack_from('>H', b, o)[0]
def be64(b, o): return struct.unpack_from('>Q', b, o)[0]

def rol32(x, r): return ((x << r) | (x >> (32 - r))) & 0xffffffff

def xfs_da_hashname(name: bytes) -> int:
    h = 0
    i = 0
    n = len(name)
    while n >= 4:
        h = (name[i] << 21 ^ name[i+1] << 14 ^ name[i+2] << 7 ^ name[i+3]
             ^ rol32(h, 7 * 4)) & 0xffffffff
        i += 4; n -= 4
    if n == 3:
        h = (name[i] << 14 ^ name[i+1] << 7 ^ name[i+2] ^ rol32(h, 7 * 3)) & 0xffffffff
    elif n == 2:
        h = (name[i] << 7 ^ name[i+1] ^ rol32(h, 7 * 2)) & 0xffffffff
    elif n == 1:
        h = (name[i] ^ rol32(h, 7 * 1)) & 0xffffffff
    return h

def main():
    dev, ino = sys.argv[1], int(sys.argv[2])
    names = [a.encode() for a in sys.argv[3:]]
    f = open(dev, 'rb', buffering=0)

    sup = f.read(4096)
    magic, = struct.unpack_from('<I', sup, 0)
    assert magic == 0x5346584D, f"no MXFS envelope magic at sector 0 (got {magic:#x})"
    data_off, = struct.unpack_from('<Q', sup, 88)
    print(f"envelope: xfs_data_offset={data_off}")

    f.seek(data_off)
    sb = f.read(512)
    assert sb[0:4] == b'XFSB', "no XFS sb at data offset"
    blksz   = be32(sb, 4)
    agblocks = be32(sb, 84)
    agcount  = be32(sb, 88)
    isize    = be16(sb, 104)
    inopblock = be16(sb, 106)
    blocklog = sb[120]; inopblog = sb[123]; agblklog = sb[124]
    print(f"sb: blksz={blksz} agblocks={agblocks} agcount={agcount} isize={isize} "
          f"inopblock={inopblock} agblklog={agblklog} inopblog={inopblog}")

    def fsb_to_byte(fsb):
        agno = fsb >> agblklog
        agbno = fsb & ((1 << agblklog) - 1)
        return data_off + (agno * agblocks + agbno) * blksz

    inoblog = agblklog + inopblog
    agno = ino >> inoblog
    agino = ino & ((1 << inoblog) - 1)
    agbno = agino >> inopblog
    ioff = agino & (inopblock - 1)
    di_addr = data_off + (agno * agblocks + agbno) * blksz + ioff * isize
    f.seek(di_addr)
    di = f.read(isize)
    assert di[0:2] == b'IN', f"dinode magic bad at {di_addr}: {di[0:2]!r}"
    di_mode = be16(di, 2)
    di_version = di[4]
    di_format = di[5]
    di_nlink = be32(di, 16)
    di_size = be64(di, 56)
    di_nextents = be32(di, 76)
    di_gen = be32(di, 92)
    print(f"dinode ino={ino}: mode={di_mode:#o} v={di_version} fmt={di_format} "
          f"nlink={di_nlink} size={di_size} nextents={di_nextents} gen={di_gen}")
    assert di_format == 2, "not extents format"
    lit = 176 if di_version == 3 else 100

    leafblk = (32 << 30) // blksz   # XFS_DIR2_LEAF_OFFSET / blksz
    exts = []
    for i in range(di_nextents):
        l0 = be64(di, lit + i * 16)
        l1 = be64(di, lit + i * 16 + 8)
        startoff = (l0 & 0x7FFFFFFFFFFFFFFF) >> 9
        startblock = ((l0 & 0x1FF) << 43) | (l1 >> 21)
        blockcount = l1 & 0x1FFFFF
        exts.append((startoff, startblock, blockcount))
        kind = 'LEAF' if startoff >= leafblk else 'DATA'
        print(f"  ext[{i}] off={startoff} fsb={startblock} len={blockcount} {kind} "
              f"byte={fsb_to_byte(startblock)}")

    for name in names:
        print(f"hash(\"{name.decode()}\") = {xfs_da_hashname(name):#010x}")

    # dir3 leaf/node block layout: xfs_da3_blkinfo = forw(0,4) back(4,4)
    # magic(8,2) pad(10,2) crc(12,4) blkno(16,8) lsn(24,8) uuid(32,16)
    # owner(48,8); xfs_dir3_leaf_hdr adds count(56,2) stale(58,2) pad(60,4);
    # leaf entries {hashval(4), address(4)} start at 64.
    for (soff, sblk, cnt) in exts:
        if soff < leafblk:
            continue
        for j in range(cnt):
            addr = fsb_to_byte(sblk + j)
            f.seek(addr)
            blk = f.read(blksz)
            m = be16(blk, 8)
            m0 = be32(blk, 0)
            print(f"leaf block off={soff + j} byte={addr} magic@8={m:#x} "
                  f"({'LEAF1' if m == 0x3DF1 else 'LEAFN' if m == 0x3DFF else 'NODE' if m == 0x3EBE else f'??? (m0={m0:#x})'})")
            if m not in (0x3DF1, 0x3DFF):
                continue
            owner = be64(blk, 48)
            count = be16(blk, 56)
            stale = be16(blk, 58)
            print(f"  owner={owner} count={count} stale={stale}")
            prev = -1
            viol = 0
            for k in range(count):
                hv = be32(blk, 64 + k * 8)
                ad = be32(blk, 64 + k * 8 + 4)
                st = ' STALE' if ad == 0xFFFFFFFF else ''
                flag = ''
                if hv < prev:
                    viol += 1
                    flag = '  <<< SORT VIOLATION'
                hit = ''
                for name in names:
                    if hv == xfs_da_hashname(name):
                        hit = f'  <== hash({name.decode()})'
                if flag or hit or k < 3 or k >= count - 3:
                    print(f"  ent[{k}] hash={hv:#010x} addr={ad:#010x}{st}{flag}{hit}")
                prev = hv
            print(f"  sort violations: {viol}")

if __name__ == '__main__':
    main()

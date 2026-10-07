#!/usr/bin/env python3
"""mxfs_dinode.py — print chosen dinodes of an MXFS image, read-only.

For each inode number: mode, nlink, gen, crtime (UTC, ns), size, format, and
for a shortform directory its '..' (the parent the directory names).  Built to
tell a child whose '..' names a reused incarnation of its removed parent (the
parent's crtime is LATER than the child's) from a child a live parent lost.

With --entries, a directory's entries too, one "  name -> ino" line each: a
shortform directory's from the inode, an extent-form one's from every data
block its data fork maps below the leaf offset (32 GiB).  A check names a
damaged directory only by its inode number; this walks from it to its path.

Usage: tools/mxfs_dinode.py --img PATH [--xfs-off N] [--entries] INO [INO...]
  --xfs-off byte offset of the XFS region inside the envelope (default: read
            from `tools/chk_mxfs -v` line `xfs_data_offset=N`)
"""
import datetime, os, struct, subprocess, sys

def be16(b, o): return struct.unpack_from(">H", b, o)[0]
def be32(b, o): return struct.unpack_from(">I", b, o)[0]
def be64(b, o): return struct.unpack_from(">Q", b, o)[0]

DI_FLAGS2_BIGTIME = 1 << 3
SB_INCOMPAT_BIGTIME = 1 << 3

def crtime(dip, bigtime):
    """di_crtime at 0x90: bigtime is ns since 1901-12-13 (epoch - 2^31 s),
    otherwise be32 seconds + be32 nanoseconds."""
    if bigtime:
        ns = be64(dip, 0x90) - (1 << 31) * 1000000000
        return ns
    return be32(dip, 0x90) * 1000000000 + be32(dip, 0x94)

def fmt_ns(ns):
    t = datetime.datetime.fromtimestamp(ns // 1000000000, datetime.timezone.utc)
    return "%s.%09dZ" % (t.strftime("%Y-%m-%dT%H:%M:%S"), ns % 1000000000)

MXFS_DIR3_BLOCK_MAGIC = 0x4d444233   # MDB3: a single-block directory
MXFS_DIR3_DATA_MAGIC = 0x4d444433    # MDD3: a data block of a larger one
DIR3_DATA_HDR = 64                   # dir3 block header + best-free table + pad
SB_INCOMPAT_FTYPE = 1 << 0
DI_FLAGS2_NREXT64 = 1 << 4
DIR2_LEAF_OFFSET = 32 << 30          # data blocks lie below this byte offset

def sf_entries(dip, ftype):
    """A shortform directory's entries: (name, ino), '..' first."""
    sf = dip[0xb0:]
    count, i8 = sf[0], sf[1]
    isz = 8 if i8 else 4
    out = [("..", be64(sf, 2) if i8 else be32(sf, 2))]
    p = 2 + isz
    for _ in range(count):
        n = sf[p]
        name = sf[p + 3:p + 3 + n].decode(errors="replace")
        q = p + 3 + n + (1 if ftype else 0)
        out.append((name, be64(sf, q) if i8 else be32(sf, q)))
        p = q + isz
    return out

def block_entries(blk, ftype):
    """A directory data block's live entries: (name, ino).  Walks from the
    header; an unused span is skipped by its length, a live entry is trusted
    only if its tag names its own offset, and a single-block directory ends
    where its leaf table begins."""
    end = len(blk)
    if be32(blk, 0) == MXFS_DIR3_BLOCK_MAGIC:
        count = be32(blk, end - 8)
        end = end - 8 - 8 * count
    out, off = [], DIR3_DATA_HDR
    while off + 16 <= end:
        if be16(blk, off) == 0xffff:
            ln = be16(blk, off + 2)
            if ln < 8 or ln % 8:
                out.append(("<bad unused length %d at %d>" % (ln, off), 0))
                break
            off += ln
            continue
        n = blk[off + 8]
        size = (8 + 1 + n + (1 if ftype else 0) + 2 + 7) & ~7
        if off + size > end or be16(blk, off + size - 2) != off:
            out.append(("<entry at %d fails its tag>" % off, 0))
            break
        out.append((blk[off + 9:off + 9 + n].decode(errors="replace"), be64(blk, off)))
        off += size
    return out

def main():
    args = sys.argv[1:]
    img = None
    xfs_off = None
    entries = False
    inos = []
    while args:
        a = args.pop(0)
        if a == "--img": img = args.pop(0)
        elif a == "--xfs-off": xfs_off = int(args.pop(0))
        elif a == "--entries": entries = True
        else: inos.append(int(a))
    if not img or not inos:
        print(__doc__); sys.exit(2)
    if xfs_off is None:
        here = os.path.dirname(os.path.abspath(__file__))
        out = subprocess.run([os.path.join(here, "chk_mxfs"), "-v", img],
                             capture_output=True, text=True, timeout=240).stdout
        for line in out.splitlines():
            if "xfs_data_offset=" in line:
                xfs_off = int(line.split("xfs_data_offset=")[1].split()[0]); break
        if xfs_off is None:
            print("cannot derive xfs_data_offset from chk_mxfs -v; pass --xfs-off"); sys.exit(2)
    with open(img, "rb") as f:
        f.seek(xfs_off); sb = f.read(512)
        if sb[:4] != b"MXSB":
            print("no MXSB at xfs_off=%d (magic=%r)" % (xfs_off, sb[:4])); sys.exit(2)
        bsize = be32(sb, 4); agblocks = be32(sb, 0x54)
        isize = be16(sb, 0x68); inopblock = be16(sb, 0x6A)
        inopblog = sb[0x7B]; agblklog = sb[0x7C]
        sb_bigtime = (be32(sb, 0xD8) & SB_INCOMPAT_BIGTIME) != 0
        ftype = (be32(sb, 0xD8) & SB_INCOMPAT_FTYPE) != 0
        dirblk = bsize << sb[0xC0]

        def fsb_offset(fsb):
            return xfs_off + ((fsb >> agblklog) * agblocks + (fsb & ((1 << agblklog) - 1))) * bsize
        for ino in inos:
            agno = ino >> (agblklog + inopblog)
            agino = ino & ((1 << (agblklog + inopblog)) - 1)
            agbno = agino >> inopblog
            off = (xfs_off + (agno * agblocks + agbno) * bsize
                   + (agino & (inopblock - 1)) * isize)
            f.seek(off); dip = f.read(isize)
            # MXFS carries its own dinode magic; the v3 self-number is the check
            if be64(dip, 0x98) != ino:
                print("ino=%d offset=%d: not this inode's dinode (di_ino=%d)"
                      % (ino, off, be64(dip, 0x98)))
                continue
            mode = be16(dip, 0x02); fmt = dip[0x05]
            bigtime = sb_bigtime and (be64(dip, 0x78) & DI_FLAGS2_BIGTIME) != 0
            line = ("ino=%d mode=0%o fmt=%d nlink=%d gen=%d cc=%d size=%d crtime=%s"
                    % (ino, mode, fmt, be32(dip, 0x10), be32(dip, 0x5c), be64(dip, 0x68),
                       be64(dip, 0x38), fmt_ns(crtime(dip, bigtime))))
            isdir = (mode & 0o170000) == 0o040000
            if isdir and fmt == 1:
                sf = dip[0xb0:]
                parent = be64(sf, 2) if sf[1] else be32(sf, 2)
                line += " sf_count=%d parent=%d" % (sf[0], parent)
            print(line)
            if not (entries and isdir):
                continue
            if fmt == 1:
                for name, eino in sf_entries(dip, ftype):
                    print("  %s -> %d" % (name, eino))
                continue
            if fmt != 2:
                print("  (format %d: entries not listed)" % fmt)
                continue
            nrec = be64(dip, 0x18) if be64(dip, 0x78) & DI_FLAGS2_NREXT64 else be32(dip, 0x4C)
            for i in range(nrec):
                l0, l1 = be64(dip, 0xb0 + 16 * i), be64(dip, 0xb8 + 16 * i)
                startoff = (l0 >> 9) & ((1 << 54) - 1)
                startblock = ((l0 & 0x1ff) << 43) | (l1 >> 21)
                count = l1 & ((1 << 21) - 1)
                if startoff * bsize >= DIR2_LEAF_OFFSET:
                    break
                f.seek(fsb_offset(startblock)); data = f.read(count * bsize)
                for b in range(0, len(data) - dirblk + 1, dirblk):
                    blk = data[b:b + dirblk]
                    if be32(blk, 0) not in (MXFS_DIR3_BLOCK_MAGIC, MXFS_DIR3_DATA_MAGIC):
                        print("  <block at file offset %d: magic 0x%08x>"
                              % (startoff * bsize + b, be32(blk, 0)))
                        continue
                    for name, eino in block_entries(blk, ftype):
                        print("  %s -> %d" % (name, eino))

if __name__ == "__main__":
    main()

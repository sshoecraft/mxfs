#!/usr/bin/env python3
"""mxfs_dinode.py — print chosen dinodes of an MXFS image, read-only.

For each inode number: mode, nlink, gen, crtime (UTC, ns), size, format, and
for a shortform directory its '..' (the parent the directory names).  Built to
tell a child whose '..' names a reused incarnation of its removed parent (the
parent's crtime is LATER than the child's) from a child a live parent lost.

Usage: tools/mxfs_dinode.py --img PATH [--xfs-off N] INO [INO...]
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

def main():
    args = sys.argv[1:]
    img = None
    xfs_off = None
    inos = []
    while args:
        a = args.pop(0)
        if a == "--img": img = args.pop(0)
        elif a == "--xfs-off": xfs_off = int(args.pop(0))
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
            line = ("ino=%d mode=0%o fmt=%d nlink=%d gen=%d size=%d crtime=%s"
                    % (ino, mode, fmt, be32(dip, 0x10), be32(dip, 0x5c),
                       be64(dip, 0x38), fmt_ns(crtime(dip, bigtime))))
            if (mode & 0o170000) == 0o040000 and fmt == 1:
                sf = dip[0xb0:]
                parent = be64(sf, 2) if sf[1] else be32(sf, 2)
                line += " sf_count=%d parent=%d" % (sf[0], parent)
            print(line)

if __name__ == "__main__":
    main()

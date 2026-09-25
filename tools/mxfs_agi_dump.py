#!/usr/bin/env python3
"""mxfs_agi_dump.py — decode on-platter AGI headers (+ the inobt/finobt root
block headers) of an MXFS image straight from the LUN image, read-only.

Prints, per AG: agi_count / agi_freecount / newino / agi_lsn (cycle:block —
identifies WHICH NODE'S LOG wrote the AGI last) / non-empty unlinked buckets,
and the root block header of the inobt and finobt (magic, level, numrecs, lsn,
owner).  Built for the sess399 forensics of the AGI-freecount-vs-btree +1
divergence (AG 0 / AG 5, 0.23.9 tmpfile churn).

Usage: tools/mxfs_agi_dump.py [--img PATH] [--xfs-off N] AGNO [AGNO...]
  --img     LUN image (default $MXFS_SCST_IMG or the lab file's paths image=)
  --scan    walk every inobt-allocated inode of the AG and report dead dinodes (leak signature)
  --xfs-off byte offset of the XFS region inside the envelope (default: read
            from `tools/chk_mxfs -v` output line `xfs_data_offset=N`, which is
            how the tool itself derives it; pass it explicitly to avoid the scan)
"""
import os, struct, subprocess, sys

def be32(b, o): return struct.unpack_from(">I", b, o)[0]
def be64(b, o): return struct.unpack_from(">Q", b, o)[0]
def lsn(v): return "%d:0x%x" % (v >> 32, v & 0xffffffff)

def main():
    args = sys.argv[1:]
    img = os.environ.get("MXFS_SCST_IMG") or subprocess.run(
        [os.path.join(os.path.dirname(os.path.abspath(__file__)), "mxfs_lab.sh"), "get", "paths", "image"],
        capture_output=True, text=True).stdout.strip()
    xfs_off = None
    agnos = []
    scan = False
    while args:
        a = args.pop(0)
        if a == "--img": img = args.pop(0)
        elif a == "--xfs-off": xfs_off = int(args.pop(0))
        elif a == "--scan": scan = True
        else: agnos.append(int(a))
    if not agnos:
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
        if sb[:4] != b"XFSB":
            print("no XFSB at xfs_off=%d (magic=%r)" % (xfs_off, sb[:4])); sys.exit(2)
        bsize = be32(sb, 4); agblocks = be32(sb, 84); agcount = be32(sb, 88)
        icount = be64(sb, 128); ifree = be64(sb, 136)
        print("img=%s xfs_off=%d blocksize=%d agblocks=%d agcount=%d sb_icount=%d sb_ifree=%d"
              % (img, xfs_off, bsize, agblocks, agcount, icount, ifree))
        for agno in agnos:
            base = xfs_off + agno * agblocks * bsize
            f.seek(base + 1024); agi = f.read(512)
            if agi[:4] != b"XAGI":
                print("AG %d: bad AGI magic %r" % (agno, agi[:4])); continue
            count = be32(agi, 16); root = be32(agi, 20); level = be32(agi, 24)
            freecount = be32(agi, 28); newino = be32(agi, 32); dirino = be32(agi, 36)
            buckets = [(i, be32(agi, 40 + 4 * i)) for i in range(64)]
            nonempty = [(i, v) for i, v in buckets if v != 0xffffffff]
            agi_lsn = be64(agi, 320); froot = be32(agi, 328); flevel = be32(agi, 332)
            print("AG %d AGI: count=%d freecount=%d newino=%d dirino=%d root=%d level=%d fino_root=%d fino_level=%d lsn=%s buckets_nonempty=%s"
                  % (agno, count, freecount, newino, dirino, root, level, froot, flevel, lsn(agi_lsn),
                     ",".join("%d:0x%x" % (i, v) for i, v in nonempty) or "none"))
            for name, blk in (("inobt", root), ("finobt", froot)):
                f.seek(base + blk * bsize); h = f.read(64)
                print("  %s root blk %d: magic=%r level=%d numrecs=%d leftsib=0x%x rightsib=0x%x blkno=%d lsn=%s owner=%d"
                      % (name, blk, h[:4], struct.unpack_from(">H", h, 4)[0], struct.unpack_from(">H", h, 6)[0],
                         be32(h, 8), be32(h, 12), be64(h, 16), lsn(be64(h, 24)), be32(h, 48)))
            # Leaf records when the root is the leaf (agi_level == 1): startino, holemask, count, freecount, free mask
            if level == 1:
                f.seek(base + root * bsize); blkb = f.read(bsize)
                n = struct.unpack_from(">H", blkb, 6)[0]
                for r in range(n):
                    o = 56 + r * 16
                    startino = be32(blkb, o); holemask = struct.unpack_from(">H", blkb, o + 4)[0]
                    cnt = blkb[o + 6]; fc = blkb[o + 7]; free = be64(blkb, o + 8)
                    print("  inobt rec %d: startino=%d holemask=0x%x count=%d freecount=%d free=0x%016x" % (r, startino, holemask, cnt, fc, free))
            if flevel == 1:
                f.seek(base + froot * bsize); blkb = f.read(bsize)
                n = struct.unpack_from(">H", blkb, 6)[0]
                for r in range(n):
                    o = 56 + r * 16
                    startino = be32(blkb, o); fc = blkb[o + 7]; free = be64(blkb, o + 8)
                    print("  finobt rec %d: startino=%d freecount=%d free=0x%016x" % (r, startino, fc, free))
            if scan and level == 1:
                # Walk every inobt-ALLOCATED inode of the AG and read its dinode:
                # an allocated slot whose dinode is dead (mode 0, or nlink 0 off
                # every bucket) is a leaked inode — the signature of a free that
                # reached the AGI count but not the btrees.
                isize = struct.unpack_from(">H", sb, 104)[0]; inopb = struct.unpack_from(">H", sb, 106)[0]
                agblklog = sb[124]; inopblog = sb[123]
                agshift = agblklog + inopblog
                f.seek(base + root * bsize); blkb = f.read(bsize)
                n = struct.unpack_from(">H", blkb, 6)[0]
                dead = 0; live = 0
                for r in range(n):
                    o = 56 + r * 16
                    startino = be32(blkb, o); free = be64(blkb, o + 8)
                    for k in range(64):
                        if free & (1 << k):
                            continue
                        agino = startino + k
                        f.seek(base + (agino // inopb) * bsize + (agino % inopb) * isize)
                        d = f.read(176)
                        magic = d[:2]; mode = struct.unpack_from(">H", d, 2)[0]
                        nlink = be32(d, 16); gen = be32(d, 84); nu = be32(d, 88); ver = d[4]
                        if magic != b"IN" or mode == 0 or nlink == 0:
                            dead += 1
                            print("  DEAD-ALLOCATED agino=%d ino=%d magic=%r ver=%d mode=0%o nlink=%d gen=%d next_unlinked=0x%x"
                                  % (agino, (agno << agshift) + agino, magic, ver, mode, nlink, gen, nu))
                        else:
                            live += 1
                print("  scan: allocated=%d live=%d dead=%d" % (live + dead, live, dead))

if __name__ == "__main__":
    main()

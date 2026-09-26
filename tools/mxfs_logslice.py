#!/usr/bin/env python3
"""
mxfs_logslice.py — read-only forensic decoder for one MXFS per-node XFS log
slice, straight off the backing image / block device (envelope-aware).

Why this exists (sess411): a survivor's foreign replay of a live-fenced
victim's slice failed with -117 (di_magic mismatch on an inode item) and the
only record of WHAT was in that slice was the kernel's own probe lines.  XFS
userspace tools cannot be pointed at an MXFS device (the on-disk envelope puts
the XFS superblock at mxfs_ondisk_super.xfs_data_offset, and the log is cut
into per-node slices), so this tool parses:

  * the 4KB mxfs_ondisk_super at byte 0 (include/mxfs/mxfs_super.h),
  * the XFS superblock at xfs_data_offset (geometry: blocklog, agblocks,
    agblklog, logstart, inodesize, inopblog),
  * the requested slice: slice_daddr = FSB_TO_DADDR(sb_logstart) +
    slice * xfs_log_slice_bblks (identical to xfs_log.c
    mxfs_xlog_recover_foreign_slice), length xfs_log_slice_bblks BBs,

and decodes every xlog_rec_header in the slice (cycle-stamp unpacking per
XLOG_HEADER_CYCLE_SIZE; logbsize<=32k -> one header block), reassembles
transactions from op headers exactly like xlog_recover_process_ophdr /
xlog_recover_add_to_trans / add_to_cont_trans, and prints each transaction's
items (XFS_LI_INODE ino/blkno/boffset/core fields, XFS_LI_ICREATE
ag/agbno/count/length/gen, XFS_LI_BUF blkno/len/blft, others by type).

It reads with O_DIRECT (dd iflag=direct) so a stale page-cache copy of the
image on the host can never masquerade as the platter (the SCST vdisk_fileio
target writes o_direct).  It never writes.

Usage:
  mxfs_logslice.py IMAGE --slice N [--ino INO] [--agbno AGNO:AGBNO]
                         [--lsn HEX] [--all] [--records]
  mxfs_logslice.py IMAGE --cluster DADDR [--len BB]      # dump dinode magics
  mxfs_logslice.py IMAGE --geom                          # geometry only

  --slice N     decode slice N (== the victim's heartbeat slot)
  --records     list every log record (blk, cycle, lsn, tail_lsn, len, ops)
  --all         print every transaction (default: only those matching a filter,
                or a summary when no filter is given)
  --ino INO     print transactions whose inode items / icreate ranges cover INO
  --agbno A:B   print transactions with an icreate or buf item covering AG A
                block B (buf match = blkno range covers the block's daddr)
  --lsn HEX     print the transaction(s) with this r_lsn
  --cluster D   read an inode cluster at XFS daddr D (default 32 BB) and print
                each 512B dinode's magic / ino / mode / nlink / gen
"""
import argparse
import os
import struct
import subprocess
import sys

BBSIZE = 512
MXFS_LOG_HEADER_MAGIC_NUM = 0xFEED4D58
XLOG_HEADER_CYCLE_SIZE = 32 * 1024
XLOG_CYCLE_DATA_SIZE = XLOG_HEADER_CYCLE_SIZE // BBSIZE

XLOG_START_TRANS = 0x01
XLOG_COMMIT_TRANS = 0x02
XLOG_CONTINUE_TRANS = 0x04
XLOG_WAS_CONT_TRANS = 0x08
XLOG_END_TRANS = 0x10
XLOG_UNMOUNT_TRANS = 0x20

LI_NAMES = {
    0x1236: "EFI", 0x1237: "EFD", 0x1238: "IUNLINK", 0x123b: "INODE",
    0x123c: "BUF", 0x123d: "DQUOT", 0x123e: "QUOTAOFF", 0x123f: "ICREATE",
    0x1240: "RUI", 0x1241: "RUD", 0x1242: "CUI", 0x1243: "CUD",
    0x1244: "BUI", 0x1245: "BUD", 0x1246: "ATTRI", 0x1247: "ATTRD",
    0x1248: "XMI", 0x1249: "XMD", 0x124a: "EFI_RT", 0x124b: "EFD_RT",
    0x124c: "RUI_RT", 0x124d: "RUD_RT", 0x124e: "CUI_RT", 0x124f: "CUD_RT",
    0x12c0: "MXFS_RELMARK",
}
BLFT_NAMES = {
    0: "UNKNOWN", 1: "UDQUOT", 2: "PDQUOT", 3: "GDQUOT", 4: "BTREE",
    5: "AGF", 6: "AGFL", 7: "AGI", 8: "DINO", 9: "SYMLINK", 10: "DIR_BLOCK",
    11: "DIR_DATA", 12: "DIR_FREE", 13: "DIR_LEAF1", 14: "DIR_LEAFN",
    15: "DA_NODE", 16: "ATTR_LEAF", 17: "ATTR_RMT", 18: "SB",
    19: "RTBITMAP", 20: "RTSUMMARY",
}
XFS_BLF_INODE_BUF = 0x1
XFS_BLF_CANCEL = 0x2
XFS_BLF_UDQUOT_BUF = 0x4
XFS_BLF_PDQUOT_BUF = 0x8
XFS_BLF_GDQUOT_BUF = 0x10
XFS_BLF_INODE_BUF_SHARED = 0x20  # hmm: upstream name XFS_BLF_INODE_BUF_SHARED? kept as value

MXFS_FORMAT_MAGIC = 0x5346584D


def direct_read(path, offset, length):
    """Read [offset, offset+length) via dd iflag=direct (page-cache-proof)."""
    if offset % BBSIZE or length % BBSIZE:
        raise SystemExit("direct_read: unaligned offset/length %d/%d" % (offset, length))
    bs = 1 << 20
    while offset % bs or length % bs:
        bs >>= 1
    cmd = ["dd", "if=%s" % path, "iflag=direct", "bs=%d" % bs,
           "skip=%d" % (offset // bs), "count=%d" % (length // bs),
           "status=none"]
    out = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if out.returncode != 0 or len(out.stdout) != length:
        raise SystemExit("dd failed rc=%d got=%d want=%d: %s" %
                         (out.returncode, len(out.stdout), length, out.stderr.decode(errors="replace")))
    return out.stdout


class Geom:
    pass


def read_geom(path):
    g = Geom()
    sup = direct_read(path, 0, 4096)
    (magic, version, flags, crc) = struct.unpack_from("<IIII", sup, 0)
    if magic != MXFS_FORMAT_MAGIC:
        raise SystemExit("no mxfs super magic at byte 0 (got 0x%08x)" % magic)
    g.mx_version, g.mx_flags = version, flags
    (g.device_size, g.xfs_data_size, g.journal_offset, g.journal_size,
     g.disklock_offset, g.disklock_size) = struct.unpack_from("<QQQQQQ", sup, 32)
    (g.max_nodes, g.journal_slot_sectors) = struct.unpack_from("<II", sup, 80)
    (g.xfs_data_offset,) = struct.unpack_from("<Q", sup, 88)
    (g.log_node_count, g.log_slice_bblks, g.proto_gen) = struct.unpack_from("<III", sup, 96)
    (g.rman_offset, g.rman_size) = struct.unpack_from("<QQ", sup, 112)

    sb = direct_read(path, g.xfs_data_offset, 4096)
    if sb[0:4] != b"MXSB":
        raise SystemExit("no MXSB at xfs_data_offset=%d" % g.xfs_data_offset)
    g.blocksize = struct.unpack_from(">I", sb, 4)[0]
    g.dblocks = struct.unpack_from(">Q", sb, 8)[0]
    g.uuid = sb[32:48]
    g.logstart = struct.unpack_from(">Q", sb, 48)[0]
    g.agblocks, g.agcount = struct.unpack_from(">II", sb, 84)
    g.logblocks = struct.unpack_from(">I", sb, 96)[0]
    g.sectsize, g.inodesize, g.inopblock = struct.unpack_from(">HHH", sb, 102)
    (g.blocklog, g.sectlog, g.inodelog, g.inopblog, g.agblklog) = struct.unpack_from("BBBBB", sb, 120)
    g.bb_per_block = g.blocksize // BBSIZE
    g.ino_agino_bits = g.agblklog + g.inopblog
    return g


def fsb_to_daddr(g, fsb):
    agno = fsb >> g.agblklog
    agbno = fsb & ((1 << g.agblklog) - 1)
    return (agno * g.agblocks + agbno) * g.bb_per_block


def agb_to_daddr(g, agno, agbno):
    return (agno * g.agblocks + agbno) * g.bb_per_block


def daddr_to_ag(g, daddr):
    blk = daddr // g.bb_per_block
    return blk // g.agblocks, blk % g.agblocks


def ino_split(g, ino):
    agno = ino >> g.ino_agino_bits
    agino = ino & ((1 << g.ino_agino_bits) - 1)
    agbno = agino >> g.inopblog
    off = agino & ((1 << g.inopblog) - 1)
    return agno, agino, agbno, off


def print_geom(g):
    print("mxfs super: version=%d flags=0x%x max_nodes=%d xfs_data_offset=%d log_node_count=%d "
          "log_slice_bblks=%d proto_gen=%d rman_offset=%d rman_size=%d" %
          (g.mx_version, g.mx_flags, g.max_nodes, g.xfs_data_offset, g.log_node_count,
           g.log_slice_bblks, g.proto_gen, g.rman_offset, g.rman_size))
    print("xfs sb: blocksize=%d dblocks=%d agblocks=%d agcount=%d logstart(fsb)=%d logblocks=%d "
          "inodesize=%d inopblock=%d blocklog=%d inodelog=%d inopblog=%d agblklog=%d" %
          (g.blocksize, g.dblocks, g.agblocks, g.agcount, g.logstart, g.logblocks,
           g.inodesize, g.inopblock, g.blocklog, g.inodelog, g.inopblog, g.agblklog))
    logd = fsb_to_daddr(g, g.logstart)
    print("log daddr=%d (slice i at daddr %d + i*%d)" % (logd, logd, g.log_slice_bblks))


def lsn_str(lsn):
    return "0x%x (cycle %d blk %d)" % (lsn, lsn >> 32, lsn & 0xffffffff)


class Rec:
    __slots__ = ("blk", "cycle", "version", "len", "lsn", "tail_lsn", "crc", "prev_block",
                 "num_logops", "fmt", "size", "hblks", "bblks", "data")


def parse_records(slice_bytes):
    """Scan the slice for record headers; return list of Rec in block order."""
    recs = []
    nbb = len(slice_bytes) // BBSIZE
    blk = 0
    while blk < nbb:
        off = blk * BBSIZE
        magic = struct.unpack_from(">I", slice_bytes, off)[0]
        if magic != MXFS_LOG_HEADER_MAGIC_NUM:
            blk += 1
            continue
        r = Rec()
        r.blk = blk
        (r.cycle, r.version, r.len) = struct.unpack_from(">III", slice_bytes, off + 4)
        (r.lsn, r.tail_lsn) = struct.unpack_from(">QQ", slice_bytes, off + 16)
        r.crc = struct.unpack_from("<I", slice_bytes, off + 32)[0]
        (r.prev_block, r.num_logops) = struct.unpack_from(">II", slice_bytes, off + 36)
        cycle_data = list(struct.unpack_from(">%dI" % XLOG_CYCLE_DATA_SIZE, slice_bytes, off + 44))
        (r.fmt,) = struct.unpack_from(">I", slice_bytes, off + 44 + 4 * XLOG_CYCLE_DATA_SIZE)
        (r.size,) = struct.unpack_from(">I", slice_bytes, off + 44 + 4 * XLOG_CYCLE_DATA_SIZE + 4 + 16)
        if r.len == 0 or r.len > 2 * 1024 * 1024 or r.cycle == 0:
            # header of an unused/zeroed iclog or garbage — skip this block only
            recs.append(r)
            r.hblks = 1
            r.bblks = 0
            r.data = b""
            blk += 1
            continue
        if (r.version & 2) and r.size > XLOG_HEADER_CYCLE_SIZE:
            r.hblks = (r.size + XLOG_HEADER_CYCLE_SIZE - 1) // XLOG_HEADER_CYCLE_SIZE
        else:
            r.hblks = 1
        r.bblks = (r.len + BBSIZE - 1) // BBSIZE
        # extended headers (only when hblks > 1): each has xh_cycle + 64 cycle words
        for h in range(1, r.hblks):
            xoff = off + h * BBSIZE
            cycle_data += list(struct.unpack_from(">%dI" % XLOG_CYCLE_DATA_SIZE, slice_bytes, xoff + 4))
        dstart = off + r.hblks * BBSIZE
        dend = dstart + r.bblks * BBSIZE
        if dend > len(slice_bytes):
            # wraps the end of the slice: circular log — join the tail end + head
            data = bytearray(slice_bytes[dstart:]) + bytearray(slice_bytes[0:dend - len(slice_bytes)])
        else:
            data = bytearray(slice_bytes[dstart:dend])
        for i in range(r.bblks):
            if i < len(cycle_data):
                struct.pack_into(">I", data, i * BBSIZE, cycle_data[i])
        r.data = bytes(data[:r.len])
        recs.append(r)
        blk += r.hblks + r.bblks
    return recs


class Txn:
    def __init__(self, tid, lsn, rec):
        self.tid = tid
        self.lsn = lsn
        self.start_rec = rec
        self.regions = []       # list of bytearray
        self.committed = False
        self.commit_rec = None
        self.items = None


def assemble_transactions(recs, valid_only=None):
    """Walk records in LSN order, return list of committed Txn (and open ones)."""
    order = sorted([r for r in recs if r.data], key=lambda r: r.lsn)
    if valid_only:
        lo, hi = valid_only
        order = [r for r in order if lo <= r.lsn <= hi]
    open_t = {}
    done = []
    for r in order:
        p = 0
        n = 0
        d = r.data
        while p + 12 <= len(d) and n < r.num_logops:
            (tid, olen) = struct.unpack_from(">II", d, p)
            clientid, flags = d[p + 8], d[p + 9]
            p += 12
            payload = d[p:p + olen]
            p += olen
            n += 1
            if clientid == 0xAA:        # XFS_LOG client: unmount record etc.
                continue
            if flags & XLOG_START_TRANS:
                open_t[tid] = Txn(tid, r.lsn, r)
                continue
            t = open_t.get(tid)
            if t is None:
                continue
            f = flags & ~XLOG_END_TRANS
            if f & XLOG_WAS_CONT_TRANS:
                f &= ~XLOG_CONTINUE_TRANS
            if f in (0, XLOG_CONTINUE_TRANS):
                t.regions.append(bytearray(payload))
            elif f == XLOG_WAS_CONT_TRANS:
                if t.regions:
                    t.regions[-1] += payload
                else:
                    t.regions.append(bytearray(payload))
            elif f == XLOG_COMMIT_TRANS:
                t.committed = True
                t.commit_rec = r
                t.items = split_items(t.regions)
                done.append(t)
                del open_t[tid]
            else:
                # unexpected (UNMOUNT / stray START) — drop
                pass
    return done, list(open_t.values())


def split_items(regions):
    items = []
    if not regions:
        return items
    th = regions[0]
    hdr = None
    if len(th) >= 16:
        (th_magic, th_type, th_tid, th_num) = struct.unpack_from("<IIII", th, 0)
        hdr = (th_magic, th_type, th_tid, th_num)
    items.append(("TRANS_HDR", hdr, [th]))
    cur = None
    need = 0
    for reg in regions[1:]:
        if cur is None:
            if len(reg) < 4:
                items.append(("SHORT", None, [reg]))
                continue
            (t, sz) = struct.unpack_from("<HH", reg, 0)
            cur = (t, [reg])
            need = sz
        else:
            cur[1].append(reg)
        if len(cur[1]) >= need:
            items.append((LI_NAMES.get(cur[0], "0x%x" % cur[0]), cur[0], cur[1]))
            cur = None
    if cur is not None:
        items.append((LI_NAMES.get(cur[0], "0x%x" % cur[0]) + "(PARTIAL %d/%d)" % (len(cur[1]), need), cur[0], cur[1]))
    return items


def describe_item(g, name, t, regs):
    r0 = regs[0]
    if t == 0x123b and len(r0) >= 56:
        (fields, asize, dsize) = struct.unpack_from("<IHH", r0, 4)
        ino = struct.unpack_from("<Q", r0, 16)[0]
        (blkno, ilen, boff) = struct.unpack_from("<qii", r0, 40)
        core = ""
        if len(regs) >= 2 and len(regs[1]) >= 104:
            c = regs[1]
            magic, mode = struct.unpack_from("<HH", c, 0)
            ver = c[4]
            nlink = struct.unpack_from("<I", c, 16)[0]
            size = struct.unpack_from("<Q", c, 56)[0]
            gen = struct.unpack_from("<I", c, 92)[0]
            cc = struct.unpack_from("<Q", c, 104)[0] if len(c) >= 112 else -1
            core = " core{magic=0x%04x mode=0%o v%d nlink=%d size=%d gen=%u cc=%d}" % (
                magic, mode, ver, nlink, size, gen, cc)
        agno, agino, agbno, off = ino_split(g, ino)
        return "INODE ino=%d (ag%d agbno=%d off=%d) fields=0x%x blkno=%d len=%d boff=%d regs=%d%s" % (
            ino, agno, agbno, off, fields, blkno, ilen, boff, len(regs), core)
    if t == 0x123f and len(r0) >= 28:
        (ag, agbno, count, isize, length, gen) = struct.unpack_from(">IIIIII", r0, 4)
        return "ICREATE ag=%d agbno=%d count=%d isize=%d length=%d gen=%u daddr=%d..+%d" % (
            ag, agbno, count, isize, length, gen, agb_to_daddr(g, ag, agbno), length * g.bb_per_block)
    if t == 0x123c and len(r0) >= 24:
        (flags, blen) = struct.unpack_from("<HH", r0, 4)
        blkno = struct.unpack_from("<q", r0, 8)[0]
        mapsz = struct.unpack_from("<I", r0, 16)[0]
        blft = (flags >> 11) & 0x1f
        agno, agbno = daddr_to_ag(g, blkno)
        fl = []
        if flags & XFS_BLF_INODE_BUF:
            fl.append("INODE_BUF")
        if flags & XFS_BLF_CANCEL:
            fl.append("CANCEL")
        return "BUF blkno=%d (ag%d agbno=%d) len=%d blft=%s flags=0x%x%s map_words=%d regs=%d fmtlen=%d" % (
            blkno, agno, agbno, blen, BLFT_NAMES.get(blft, str(blft)), flags,
            ("[" + ",".join(fl) + "]") if fl else "", mapsz, len(regs), len(r0))
    if t in (0x1236, 0x1237) and len(r0) >= 16:
        return "%s regs=%d fmtlen=%d" % (name, len(regs), len(r0))
    return "%s regs=%d fmtlen=%d" % (name, len(regs), len(r0))


def txn_matches(g, t, args):
    if args.all:
        return True
    if args.lsn is not None and t.lsn == args.lsn:
        return True
    for name, ty, regs in t.items:
        r0 = regs[0]
        if args.ino is not None:
            if ty == 0x123b and len(r0) >= 24 and struct.unpack_from("<Q", r0, 16)[0] == args.ino:
                return True
            if ty == 0x123f and len(r0) >= 28:
                (ag, agbno, count, isize, length, gen) = struct.unpack_from(">IIIIII", r0, 4)
                iagno, iagino, iagbno, ioff = ino_split(g, args.ino)
                if ag == iagno and agbno <= iagbno < agbno + length:
                    return True
        if args.agbno is not None:
            A, B = args.agbno
            want = agb_to_daddr(g, A, B)
            if ty == 0x123f and len(r0) >= 28:
                (ag, agbno, count, isize, length, gen) = struct.unpack_from(">IIIIII", r0, 4)
                if ag == A and agbno <= B < agbno + length:
                    return True
            if ty == 0x123c and len(r0) >= 24:
                (flags, blen) = struct.unpack_from("<HH", r0, 4)
                blkno = struct.unpack_from("<q", r0, 8)[0]
                if blkno <= want < blkno + blen:
                    return True
            if ty == 0x123b and len(r0) >= 56:
                (blkno, ilen, boff) = struct.unpack_from("<qii", r0, 40)
                if blkno <= want < blkno + ilen:
                    return True
    return False


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("image")
    ap.add_argument("--geom", action="store_true")
    ap.add_argument("--slice", type=int)
    ap.add_argument("--records", action="store_true")
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--ino", type=int)
    ap.add_argument("--agbno", type=str, help="AGNO:AGBNO")
    ap.add_argument("--lsn", type=lambda s: int(s, 16))
    ap.add_argument("--cluster", type=int, help="XFS daddr of an inode cluster to dump")
    ap.add_argument("--len", type=int, default=32, help="BBs to dump for --cluster (default 32)")
    ap.add_argument("--whole", action="store_true", help="decode the whole slice, not just [tail,head]")
    ap.add_argument("--raw-out", type=str, metavar="FILE",
                    help="also write the slice's raw bytes (envelope-correct offset) to FILE")
    args = ap.parse_args()
    if args.agbno:
        a, b = args.agbno.split(":")
        args.agbno = (int(a), int(b))

    g = read_geom(args.image)
    if args.geom or (args.slice is None and args.cluster is None):
        print_geom(g)
        if args.slice is None and args.cluster is None:
            return

    if args.cluster is not None:
        off = g.xfs_data_offset + args.cluster * BBSIZE
        buf = direct_read(args.image, off, args.len * BBSIZE)
        agno, agbno = daddr_to_ag(g, args.cluster)
        print("cluster daddr=%d (ag%d agbno=%d) bytes=%d @ image offset %d" % (
            args.cluster, agno, agbno, len(buf), off))
        step = g.inodesize
        for i in range(0, len(buf), step):
            magic, mode = struct.unpack_from(">HH", buf, i)
            ver = buf[i + 4]
            nlink = struct.unpack_from(">I", buf, i + 16)[0]
            gen = struct.unpack_from(">I", buf, i + 92)[0]
            nunl = struct.unpack_from(">I", buf, i + 96)[0]
            extra = ""
            if ver == 3:
                cc = struct.unpack_from(">Q", buf, i + 104)[0]
                lsn = struct.unpack_from(">Q", buf, i + 112)[0]
                dino = struct.unpack_from(">Q", buf, i + 152)[0]
                extra = " cc=%d lsn=0x%x di_ino=%d" % (cc, lsn, dino)
            print("  +%5d: magic=0x%04x%s mode=0%o v%d nlink=%d gen=%u next_unlinked=0x%x%s  first16=%s" % (
                i, magic, "" if magic == 0x4D4E else " (NOT IN)", mode, ver, nlink, gen, nunl, extra,
                buf[i:i + 16].hex()))
        return

    logd = fsb_to_daddr(g, g.logstart)
    sdaddr = logd + args.slice * g.log_slice_bblks
    off = g.xfs_data_offset + sdaddr * BBSIZE
    nbytes = g.log_slice_bblks * BBSIZE
    print("slice %d/%d: daddr=%d bblks=%d image offset=%d" % (
        args.slice, g.log_node_count, sdaddr, g.log_slice_bblks, off))
    sl = direct_read(args.image, off, nbytes)
    if args.raw_out:
        with open(args.raw_out, "wb") as rf:
            rf.write(sl)
        print("raw slice written: %s (%d bytes)" % (args.raw_out, len(sl)))
    recs = parse_records(sl)
    live = [r for r in recs if r.data]
    if not live:
        print("no log records with data found in slice")
        return
    head = max(live, key=lambda r: r.lsn)
    tail_lsn = head.tail_lsn
    print("records=%d (with data %d) head=%s tail(from head rec)=%s" % (
        len(recs), len(live), lsn_str(head.lsn), lsn_str(tail_lsn)))
    inrange = [r for r in live if tail_lsn <= r.lsn <= head.lsn]
    print("records in [tail,head]: %d, spanning blk %d..%d" % (
        len(inrange), min(r.blk for r in inrange), max(r.blk for r in inrange)))
    if args.records:
        for r in sorted(live, key=lambda r: r.lsn):
            mark = "*" if tail_lsn <= r.lsn <= head.lsn else " "
            print(" %s blk=%6d cycle=%d lsn=0x%x tail=0x%x len=%d ops=%d hblks=%d bblks=%d fmt=%d size=%d" % (
                mark, r.blk, r.cycle, r.lsn, r.tail_lsn, r.len, r.num_logops, r.hblks, r.bblks, r.fmt, r.size))
    rng = None if args.whole else (tail_lsn, head.lsn)
    done, still_open = assemble_transactions(recs, rng)
    print("transactions committed=%d open(uncommitted at head)=%d" % (len(done), len(still_open)))
    have_filter = args.all or args.ino is not None or args.agbno is not None or args.lsn is not None
    from collections import Counter
    tot = Counter()
    for t in done:
        for name, ty, regs in t.items:
            tot[name] += 1
    print("item totals: " + " ".join("%s=%d" % kv for kv in sorted(tot.items())))
    shown = 0
    for t in done:
        if have_filter and not txn_matches(g, t, args):
            continue
        if not have_filter:
            continue
        shown += 1
        hdr = t.items[0][1] if t.items else None
        print("TXN lsn=%s tid=0x%x items=%d th_type=%s th_num_items=%s commit_rec_lsn=0x%x" % (
            lsn_str(t.lsn), t.tid, len(t.items) - 1,
            ("%d" % hdr[1]) if hdr else "?", ("%d" % hdr[3]) if hdr else "?",
            t.commit_rec.lsn))
        for name, ty, regs in t.items[1:]:
            print("    " + describe_item(g, name, ty, regs))
    if not have_filter:
        print("(no filter given: use --all / --ino / --agbno / --lsn to print transactions)")
    else:
        print("shown %d transaction(s)" % shown)
    for t in still_open:
        print("OPEN(uncommitted) txn lsn=%s tid=0x%x regions=%d" % (lsn_str(t.lsn), t.tid, len(t.regions)))


if __name__ == "__main__":
    main()

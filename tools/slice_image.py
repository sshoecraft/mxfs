#!/usr/bin/env python3
"""slice_image.py — raw inspection and imaging of an MXFS filesystem's XFS log
slices, read and written O_DIRECT so the initiator page cache never answers.

The XFS internal log is carved by mkfs_mxfs into xfs_log_node_count slices of
xfs_log_slice_bblks basic blocks each; slice k belongs to heartbeat slot k.
This tool exists for the D-0531 measurement (tests/d0531_stale_slice_recovery.sh):
save a slice image, replace only the blocks an incarnation never wrote, put it
back, and read the home copy of a dinode so "checkpointed or not" is a fact
read off the platter rather than a timing assumption.

  geom    DEV                         print the decoded geometry
  dump    DEV SLOT OUT                copy slice SLOT to OUT
  load    DEV SLOT IN                 write IN over slice SLOT (O_DIRECT, then fsync)
  compose CRASH OLD OUT [--keep-first N]
                                      OUT = CRASH with every all-zero 512 B block
                                      replaced by OLD's block at the same offset;
                                      the first N blocks stay as CRASH has them
  scan    DEV|IMG SBUUID [--dev]      count XFS log record headers per UUID
  dinode  DEV INO                     decode the home dinode: magic, mode, nlink, size
  digest  DEV SLOT                    md5 of slice SLOT plus its non-zero census
  find    DEV SLOT PATTERN            search slice SLOT for an ASCII byte pattern

`digest` and `find` are the SLICE-REGION ORACLE.  The authority-gate laps read
a probe file's own data block off the raw device, which is the right oracle for
the "dio" and "data" submission classes and the wrong one for "log": a journal
write lands in the writing node's log slice, where that block never looks, so
grading a log arm against it reports "nothing changed" for a write that did in
fact land.  These two answer the slice instead.  `find` is the stronger of the
pair and is what a verdict should rest on: it is content-addressed to a nonce
the lap planted in the transaction itself, so a slice the successor legitimately
rewrote during its own recovery cannot be mistaken for an old-epoch write that
arrived late.  `digest` says only whether the region moved at all.
"""
import os, struct, sys, mmap, uuid, hashlib

BLK = 512
XLOG_MAGIC = 0xFEEDBABE
DINODE_MAGIC = 0x494E  # 'IN'


def pread_direct(dev, off, length):
    fd = os.open(dev, os.O_RDONLY | os.O_DIRECT)
    try:
        # align to 4096 for the direct read
        a_off = off & ~4095
        a_len = ((off + length + 4095) & ~4095) - a_off
        m = mmap.mmap(-1, a_len)
        got = os.preadv(fd, [m], a_off)
        if got < a_len:
            raise IOError("short direct read %d/%d at %d" % (got, a_len, a_off))
        data = m.read(a_len)
        m.close()
        return data[off - a_off: off - a_off + length]
    finally:
        os.close(fd)


def pwrite_direct(dev, off, data):
    if off % 512 or len(data) % 512:
        raise ValueError("unaligned write")
    fd = os.open(dev, os.O_WRONLY | os.O_DIRECT)
    try:
        m = mmap.mmap(-1, len(data))
        m.write(data)
        done = 0
        # every memoryview over the mmap is released before the mmap is
        # closed: an unreleased slice is an exported pointer and m.close()
        # raises BufferError AFTER every block was written and fsynced —
        # the plant lands and the tool reports failure (measured s60h)
        with memoryview(m) as mv:
            while done < len(data):
                chunk = min(4 << 20, len(data) - done)
                with mv[done:done + chunk] as piece:
                    w = os.pwritev(fd, [piece], off + done)
                if w <= 0:
                    raise IOError("direct write failed at %d" % (off + done))
                done += w
        os.fsync(fd)
        m.close()
    finally:
        os.close(fd)


def geom(dev):
    sup = pread_direct(dev, 0, 4096)
    magic, version, flags = struct.unpack_from('<III', sup, 0)
    xfs_data_offset = struct.unpack_from('<Q', sup, 88)[0]
    log_node_count, slice_bblks = struct.unpack_from('<II', sup, 96)
    sb = pread_direct(dev, xfs_data_offset, 4096)
    sb_magic = struct.unpack_from('>I', sb, 0)[0]
    sb_uuid = uuid.UUID(bytes=sb[32:48])
    logstart = struct.unpack_from('>Q', sb, 48)[0]
    agblocks = struct.unpack_from('>I', sb, 84)[0]
    logblocks = struct.unpack_from('>I', sb, 96)[0]
    inodesize = struct.unpack_from('>H', sb, 104)[0]
    inopblock = struct.unpack_from('>H', sb, 106)[0]
    blocklog, sectlog, inodelog, inopblog, agblklog = struct.unpack_from('BBBBB', sb, 120)
    agno = logstart >> agblklog
    agbno = logstart & ((1 << agblklog) - 1)
    log_phys = xfs_data_offset + (agno * agblocks + agbno) * 4096
    return dict(env_magic=magic, env_version=version, env_flags=flags,
                xfs_data_offset=xfs_data_offset, log_node_count=log_node_count,
                slice_bblks=slice_bblks, slice_bytes=slice_bblks * BLK,
                sb_magic=sb_magic, sb_uuid=str(sb_uuid), logstart=logstart,
                agblocks=agblocks, logblocks=logblocks, inodesize=inodesize,
                inopblock=inopblock, inopblog=inopblog, agblklog=agblklog,
                log_phys=log_phys)


def slice_range(g, slot):
    if slot < 0 or slot >= g['log_node_count']:
        raise ValueError("slot %d outside 0..%d" % (slot, g['log_node_count'] - 1))
    return g['log_phys'] + slot * g['slice_bytes'], g['slice_bytes']


def region_digest(dev, off, ln, chunk=4 << 20):
    """md5 of [off, off+ln) read O_DIRECT, with a 512 B non-zero census."""
    h = hashlib.md5()
    zero = b'\0' * BLK
    zblocks = 0
    last_nonzero = -1
    done = 0
    while done < ln:
        n = min(chunk, ln - done)
        data = pread_direct(dev, off + done, n)
        h.update(data)
        for o in range(0, n, BLK):
            if data[o:o + BLK] == zero:
                zblocks += 1
            else:
                last_nonzero = (done + o) // BLK
        done += n
    return h.hexdigest(), zblocks, last_nonzero


def region_find(dev, off, ln, pat, chunk=4 << 20, cap=16):
    """count occurrences of `pat` in [off, off+ln), read O_DIRECT.

    Chunks carry len(pat)-1 bytes of the previous chunk so a match straddling
    a chunk boundary is still found.  That overlap cannot double-count: a match
    starting inside it needs bytes past the previous chunk's end, so the
    previous pass could not have seen it.
    """
    if not pat:
        raise ValueError("empty pattern")
    ov = len(pat) - 1
    hits = []
    total = 0
    tail = b''
    done = 0
    while done < ln:
        n = min(chunk, ln - done)
        data = pread_direct(dev, off + done, n)
        window = tail + data
        base = off + done - len(tail)
        i = window.find(pat)
        while i != -1:
            total += 1
            if len(hits) < cap:
                hits.append(base + i)
            i = window.find(pat, i + 1)
        tail = data[-ov:] if ov else b''
        done += n
    return total, hits


def scan(data, sbuuid):
    """count xlog record headers per h_fs_uuid; return (total, {uuid: n}, first_off)"""
    per = {}
    first = {}
    n = 0
    for off in range(0, len(data) - BLK + 1, BLK):
        if struct.unpack_from('>I', data, off)[0] != XLOG_MAGIC:
            continue
        n += 1
        u = str(uuid.UUID(bytes=data[off + 304: off + 320]))
        per[u] = per.get(u, 0) + 1
        first.setdefault(u, off)
    return n, per, first


def main(argv):
    if len(argv) < 2:
        print(__doc__); return 2
    cmd = argv[1]
    if cmd == 'geom':
        g = geom(argv[2])
        for k, v in g.items():
            print("%s=%s" % (k, v))
        return 0
    if cmd == 'dump':
        dev, slot, out = argv[2], int(argv[3]), argv[4]
        g = geom(dev); off, ln = slice_range(g, slot)
        data = pread_direct(dev, off, ln)
        with open(out, 'wb') as f:
            f.write(data)
        z = sum(1 for o in range(0, ln, BLK) if data[o:o + BLK] == b'\0' * BLK)
        print("dumped slot=%d off=%d bytes=%d zero_blocks=%d of %d" % (slot, off, ln, z, ln // BLK))
        return 0
    if cmd == 'load':
        dev, slot, inp = argv[2], int(argv[3]), argv[4]
        g = geom(dev); off, ln = slice_range(g, slot)
        data = open(inp, 'rb').read()
        if len(data) != ln:
            print("image is %d bytes, slice is %d" % (len(data), ln)); return 1
        pwrite_direct(dev, off, data)
        back = pread_direct(dev, off, ln)
        print("loaded slot=%d off=%d bytes=%d verify=%s" % (slot, off, ln, "OK" if back == data else "MISMATCH"))
        return 0 if back == data else 1
    if cmd == 'compose':
        crash, old, out = argv[2], argv[3], argv[4]
        # --keep-first N: the first N 512 B blocks stay as CRASH has them even
        # when zero.  xlog_find_zeroed reads block 0 first and a zero cycle
        # there means "completely zeroed log": a fresh incarnation's first
        # mount then proceeds clean and writes its records from block 0,
        # leaving the planted old records BEYOND its genuine head — the
        # layout D-0531 is about.  With block 0 planted too the first mount
        # is refused at head discovery (mismatched uuid, -117; measured s60i)
        # and the incarnation never writes anything.
        keep_first = int(argv[argv.index('--keep-first') + 1]) if '--keep-first' in argv else 0
        c = bytearray(open(crash, 'rb').read()); o = open(old, 'rb').read()
        if len(c) != len(o):
            print("image sizes differ %d vs %d" % (len(c), len(o))); return 1
        rep = 0; kept = 0
        for off in range(0, len(c), BLK):
            if off < keep_first * BLK:
                kept += 1
                continue
            if c[off:off + BLK] == b'\0' * BLK:
                if o[off:off + BLK] != b'\0' * BLK:
                    c[off:off + BLK] = o[off:off + BLK]; rep += 1
            else:
                kept += 1
        with open(out, 'wb') as f:
            f.write(bytes(c))
        print("composed: current_blocks_kept=%d old_blocks_planted=%d total=%d keep_first=%d" % (kept, rep, len(c) // BLK, keep_first))
        return 0
    if cmd == 'digest':
        dev, slot = argv[2], int(argv[3])
        g = geom(dev); off, ln = slice_range(g, slot)
        md5, zb, lastnz = region_digest(dev, off, ln)
        print("SLICE slot=%d off=%d len=%d md5=%s zero_blocks=%d nonzero_blocks=%d last_nonzero_block=%d" % (
            slot, off, ln, md5, zb, ln // BLK - zb, lastnz))
        print("SLICE_END")
        return 0
    if cmd == 'find':
        dev, slot, pat = argv[2], int(argv[3]), argv[4].encode()
        g = geom(dev); off, ln = slice_range(g, slot)
        total, hits = region_find(dev, off, ln, pat)
        print("FIND slot=%d off=%d len=%d pattern=%s hits=%d" % (slot, off, ln, argv[4], total))
        for h in hits:
            print("FIND hit=%d rel=%d" % (h, h - off))
        print("FIND_END")
        return 0
    if cmd == 'scan':
        src, sbuuid = argv[2], argv[3]
        if '--dev' in argv:
            g = geom(src)
            # the first four slices (2 GiB for all 32 over iSCSI is ~40 s);
            # --all scans every slice
            nslots = g['log_node_count'] if '--all' in argv else min(4, g['log_node_count'])
            for slot in range(nslots):
                off, ln = slice_range(g, slot)
                data = pread_direct(src, off, ln)
                n, per, first = scan(data, sbuuid)
                foreign = sum(v for k, v in per.items() if k != sbuuid)
                print("slot=%d headers=%d current=%d foreign=%d first_current_off=%s first_foreign_off=%s uuids=%s" % (
                    slot, n, per.get(sbuuid, 0), foreign, first.get(sbuuid, '-'),
                    min([first[k] for k in first if k != sbuuid], default='-'), sorted(per.keys())))
        else:
            data = open(src, 'rb').read()
            n, per, first = scan(data, sbuuid)
            foreign = sum(v for k, v in per.items() if k != sbuuid)
            print("img=%s headers=%d current=%d foreign=%d uuids=%s" % (src, n, per.get(sbuuid, 0), foreign, sorted(per.keys())))
        return 0
    if cmd == 'dinode':
        dev, ino = argv[2], int(argv[3])
        g = geom(dev)
        agno = ino >> (g['agblklog'] + g['inopblog'])
        agbno = (ino >> g['inopblog']) & ((1 << g['agblklog']) - 1)
        idx = ino & ((1 << g['inopblog']) - 1)
        off = g['xfs_data_offset'] + (agno * g['agblocks'] + agbno) * 4096 + idx * g['inodesize']
        d = pread_direct(dev, off, g['inodesize'])
        magic = struct.unpack_from('>H', d, 0)[0]
        mode = struct.unpack_from('>H', d, 2)[0]
        nlink = struct.unpack_from('>I', d, 16)[0]
        size = struct.unpack_from('>Q', d, 56)[0]
        gen = struct.unpack_from('>I', d, 0x6c)[0] if len(d) >= 0x70 else 0
        print("ino=%d agno=%d agbno=%d idx=%d off=%d magic=0x%x mode=0%o nlink=%d size=%d gen=%d state=%s" % (
            ino, agno, agbno, idx, off, magic, mode, nlink, size, gen,
            "ALLOCATED" if magic == DINODE_MAGIC and mode != 0 else ("FREE" if magic == DINODE_MAGIC else "NOMAGIC")))
        return 0
    print("unknown command %s" % cmd); return 2


if __name__ == '__main__':
    sys.exit(main(sys.argv))

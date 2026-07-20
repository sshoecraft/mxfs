#!/usr/bin/env python3
# xref_owners.py — static full-FS block-ownership cross-reference for MXFS.
#
# Walks the raw backing file (envelope-aware): every AG's inobt (inode chunk
# block claims) + every allocated inode's data fork (extent claims, extents
# and btree formats).  Any block claimed by more than one owner = a durable
# double-allocation — provable without any write history.  Run against a
# QUIESCED (unmounted) filesystem; a live mount gives transient false reads.
#
# Usage: xref_owners.py <backing-file> [--verbose]
# Exit: 0 clean, 10 = dual ownership found, 2 = parse error.
import struct, sys

def main():
    img = sys.argv[1]
    verbose = '--verbose' in sys.argv
    f = open(img, 'rb')

    sb0 = f.read(96)
    magic, = struct.unpack_from('<I', sb0, 0)
    if magic != 0x5346584D:
        print(f"not an mxfs device (magic {magic:#x})"); return 2
    xfs_off, = struct.unpack_from('<Q', sb0, 88)
    f.seek(xfs_off); sb = f.read(512)
    if sb[0:4] != b'XFSB':
        print("no XFSB at xfs_data_offset"); return 2
    blocksize, = struct.unpack_from('>I', sb, 4)
    logstart, = struct.unpack_from('>Q', sb, 48)
    agblocks, = struct.unpack_from('>I', sb, 84)
    agcount, = struct.unpack_from('>I', sb, 88)
    logblocks, = struct.unpack_from('>I', sb, 96)
    inodesize, = struct.unpack_from('>H', sb, 104)
    blocklog = sb[120]; inopblog = sb[123]; agblklog = sb[124]
    inos_per_blk = 1 << inopblog

    def agb_bytes(agno, agbno):
        return xfs_off + (agno * agblocks + agbno) * blocksize

    def fsb_split(fsb):
        return fsb >> agblklog, fsb & ((1 << agblklog) - 1)

    def rawfsb(agno, agbno):
        return agno * agblocks + agbno   # linear device block number

    claims = {}   # raw linear block -> list of owner tags
    dups = set()

    def claim(agno, agbno, count, tag):
        for i in range(count):
            b = rawfsb(agno, agbno + i)
            if b in claims:
                claims[b].append(tag)
                dups.add(b)
            else:
                claims[b] = [tag]

    # exclude the internal log range from inode-extent claims (it is owned by
    # the fs itself; sb_logstart is in fsb-encoded form)
    log_agno, log_agbno = fsb_split(logstart)
    log_first = rawfsb(log_agno, log_agbno)
    log_range = range(log_first, log_first + logblocks)

    chunks = []   # (agno, startino_agbno_base, chunk_start_absino, free_mask, holemask)
    # ---- pass 1: inobt walk per AG ----
    for agno in range(agcount):
        f.seek(agb_bytes(agno, 0) + 1024)   # AGI = sector 2 of AG block 0
        agi = f.read(512)
        if agi[0:4] != b'XAGI':
            print(f"AG{agno}: bad AGI magic {agi[0:4]}"); return 2
        root, = struct.unpack_from('>I', agi, 20)
        level, = struct.unpack_from('>I', agi, 24)

        def walk_inobt(agbno, lvl):
            f.seek(agb_bytes(agno, agbno))
            blk = f.read(blocksize)
            if blk[0:4] != b'IAB3':
                print(f"AG{agno}: inobt block agbno={agbno} bad magic {blk[0:4]}")
                return
            blvl, nrec = struct.unpack_from('>HH', blk, 4)
            hdr = 56   # short-form v5 btree header
            if blvl > 0:
                maxr = (blocksize - hdr) // 8
                for i in range(nrec):
                    p, = struct.unpack_from('>I', blk, hdr + maxr * 4 + i * 4)
                    walk_inobt(p, blvl - 1)
            else:
                for i in range(nrec):
                    startino, holemask, cnt, freecnt = struct.unpack_from(
                        '>IHBB', blk, hdr + i * 16)
                    free, = struct.unpack_from('>Q', blk, hdr + i * 16 + 8)
                    base_agbno = startino >> inopblog
                    # chunk spans 64 inodes = 64/inos_per_blk blocks; sparse
                    # chunks (holemask) omit 4-ino subregions — claim only
                    # present blocks (holemask bit i covers inos i*4..i*4+3)
                    blks = 64 // inos_per_blk
                    for b in range(blks):
                        lo_ino = b * inos_per_blk
                        present = False
                        for sub in range(lo_ino // 4, (lo_ino + inos_per_blk) // 4):
                            if not (holemask >> sub) & 1:
                                present = True
                        if present:
                            claim(agno, base_agbno + b, 1,
                                  f"ichunk:{agno}/{startino}")
                    chunks.append((agno, startino, free, holemask))
        walk_inobt(root, level)

    # ---- pass 2: every allocated inode's data fork ----
    nino = 0
    next_ext = 0
    for agno, startino, free, holemask in chunks:
        for slot in range(64):
            if (free >> slot) & 1:
                continue                     # free inode
            if (holemask >> (slot // 4)) & 1:
                continue                     # sparse hole
            ino_ag = startino + slot
            absino = (agno << (agblklog + inopblog)) | ino_ag
            agbno = ino_ag >> inopblog
            f.seek(agb_bytes(agno, agbno) + (ino_ag & (inos_per_blk - 1)) * inodesize)
            di = f.read(inodesize)
            if di[0:2] != b'IN':
                print(f"ino {absino}: bad dinode magic {di[0:2].hex()} "
                      f"(chunk {agno}/{startino} slot {slot})")
                continue
            mode, = struct.unpack_from('>H', di, 2)
            if mode == 0:
                continue                     # freed-but-not-in-free-mask? skip
            fmt = di[5]
            nx, = struct.unpack_from('>I', di, 76)
            nino += 1
            lit = 176
            exts = []
            if fmt == 2:
                for i in range(nx):
                    hi, lo = struct.unpack_from('>QQ', di, lit + i * 16)
                    sfsb = ((hi & 0x1ff) << 43) | (lo >> 21)
                    cnt = lo & ((1 << 21) - 1)
                    exts.append((sfsb, cnt))
            elif fmt == 3:
                forkoff = di[82]
                litsz = (inodesize - 176) if forkoff == 0 else forkoff * 8
                lvl, numrec = struct.unpack_from('>HH', di, lit)
                maxrec = (litsz - 4) // 16
                ptrs = [struct.unpack_from('>Q', di, lit + 4 + maxrec * 8 + i * 8)[0]
                        for i in range(numrec)]
                stack = [(p, lvl) for p in ptrs]
                while stack:
                    fsb, l = stack.pop()
                    a2, b2 = fsb_split(fsb)
                    f.seek(agb_bytes(a2, b2))
                    blk = f.read(blocksize)
                    if blk[0:4] != b'BMA3':
                        print(f"ino {absino}: bmbt fsb {fsb} bad magic {blk[0:4]}")
                        continue
                    # bmbt blocks themselves are owned blocks too
                    claim(a2, b2, 1, f"bmbt:{absino}")
                    l2, nr = struct.unpack_from('>HH', blk, 4)
                    hdr = 72
                    if l2 > 0:
                        mx = (blocksize - hdr) // 16
                        for i in range(nr):
                            p, = struct.unpack_from('>Q', blk, hdr + mx * 8 + i * 8)
                            stack.append((p, l2 - 1))
                    else:
                        for i in range(nr):
                            hi, lo = struct.unpack_from('>QQ', blk, hdr + i * 16)
                            sfsb = ((hi & 0x1ff) << 43) | (lo >> 21)
                            cnt = lo & ((1 << 21) - 1)
                            exts.append((sfsb, cnt))
            for sfsb, cnt in exts:
                a2, b2 = fsb_split(sfsb)
                first = rawfsb(a2, b2)
                if first in log_range:
                    continue
                claim(a2, b2, cnt, f"ino:{absino}")
                next_ext += 1

    print(f"scanned: {len(chunks)} chunks, {nino} allocated inodes, "
          f"{next_ext} extents, {len(claims)} claimed blocks")
    if not dups:
        print("XREF CLEAN — no dual-owned blocks")
        return 0
    print(f"XREF DUAL-OWNED BLOCKS: {len(dups)}")
    shown = 0
    for b in sorted(dups):
        agno = b // agblocks; agbno = b % agblocks
        print(f"  block agno={agno} agbno={agbno} daddr={b*8}: {claims[b]}")
        shown += 1
        if shown >= 40 and not verbose:
            print(f"  ... {len(dups)-shown} more")
            break
    return 10

sys.exit(main())

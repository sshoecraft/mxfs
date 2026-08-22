#!/usr/bin/env python3
"""xlog_slice_scan.py — offline map of an MXFS per-node XFS log slice image.

Scans a raw (or .gz) slice image for xlog record headers (h_magicno
0xFEEDbabe), prints each record's block, cycle, version, len, lsn,
tail_lsn, num_logops, and marks zero/nonzero block ranges.  Built for the
incident-474 stuck-replay analysis (torn head at a given block); generally
useful for any "why won't this slice replay" question.

Usage: xlog_slice_scan.py <slice.img[.gz]> [--around BLOCK]
"""
import gzip
import struct
import sys

BB = 512
XLOG_HEADER_MAGIC = 0xFEEDBABE


def load(path):
    if path.endswith(".gz"):
        with gzip.open(path, "rb") as f:
            return f.read()
    with open(path, "rb") as f:
        return f.read()


def cycle_lsn(lsn):
    return (lsn >> 32, lsn & 0xFFFFFFFF)


def main():
    path = sys.argv[1]
    around = None
    if "--around" in sys.argv:
        around = int(sys.argv[sys.argv.index("--around") + 1], 0)
    data = load(path)
    nblocks = len(data) // BB
    print(f"image: {path}  bytes={len(data)}  blocks={nblocks}")

    # zero/nonzero map (coarse)
    first_zero_run = None
    last_nonzero = -1
    for b in range(nblocks):
        blk = data[b * BB:(b + 1) * BB]
        if blk.count(0) != BB:
            last_nonzero = b
    print(f"last nonzero block: {last_nonzero} (0x{last_nonzero:x})")

    # record headers
    print("\nrecord headers (h_magicno match):")
    hdrs = []
    for b in range(nblocks):
        off = b * BB
        magic = struct.unpack(">I", data[off:off + 4])[0]
        if magic != XLOG_HEADER_MAGIC:
            continue
        h_cycle, h_version, h_len = struct.unpack(">IiI", data[off + 4:off + 16])
        h_lsn, h_tail_lsn = struct.unpack(">QQ", data[off + 16:off + 32])
        h_crc = struct.unpack(">I", data[off + 32:off + 36])[0]
        (h_fmt,) = struct.unpack(">i", data[off + 40:off + 44])
        (h_size, h_num_logops) = struct.unpack(">II", data[off + 48 + 16 - 8:off + 48 + 16][0:0]) if False else (0, 0)
        # xlog_rec_header layout: magic(0) cycle(4) version(8) len(12)
        # lsn(16) tail_lsn(24) crc(32) prev_block(36) num_logops(40)
        # cycle_data[64](44) fmt(300) uuid(304) size(320)
        h_cycle, h_version, h_len = struct.unpack(">III", data[off + 4:off + 16])
        h_lsn, h_tail_lsn = struct.unpack(">QQ", data[off + 16:off + 32])
        h_crc = struct.unpack(">I", data[off + 32:off + 36])[0]
        h_prev_block = struct.unpack(">i", data[off + 36:off + 40])[0]
        h_num_logops = struct.unpack(">I", data[off + 40:off + 44])[0]
        uuid = data[off + 304:off + 320].hex()
        hdrs.append((b, h_lsn, uuid))
        lc, lb = cycle_lsn(h_lsn)
        tc, tb = cycle_lsn(h_tail_lsn)
        skew = "" if lb == b else f"  <<LSN-BLOCK-SKEW lsn_blk=0x{lb:x} phys=0x{b:x}>>"
        print(f"  blk {b:7d} (0x{b:06x}) cycle={h_cycle} ver={h_version} "
              f"len={h_len} lsn={lc}:{lb} tail={tc}:{tb} "
              f"crc=0x{h_crc:08x} prev={h_prev_block} ops={h_num_logops} "
              f"uuid={uuid}{skew}")
    print(f"total headers: {len(hdrs)}")
    uuids = {}
    for b, lsn, u in hdrs:
        uuids.setdefault(u, []).append(b)
    print(f"distinct uuids: {len(uuids)}")
    for u, blks in uuids.items():
        print(f"  {u}: {len(blks)} headers, first blk {blks[0]} last blk {blks[-1]}")
    skews = [(b, lsn) for b, lsn, u in hdrs if (lsn & 0xFFFFFFFF) != b]
    print(f"lsn-block skews: {len(skews)}")
    for b, lsn in skews:
        print(f"  phys blk 0x{b:x} h_lsn {lsn >> 32}:{lsn & 0xFFFFFFFF:#x}")

    if around is not None:
        lo, hi = max(0, around - 12), min(nblocks, around + 12)
        print(f"\nblock detail {lo}..{hi} (first 16 bytes each):")
        for b in range(lo, hi):
            off = b * BB
            head = data[off:off + 16]
            z = "ZERO" if data[off:off + BB].count(0) == BB else "data"
            cyc = struct.unpack(">I", head[0:4])[0]
            print(f"  blk {b:7d} (0x{b:06x}) [{z}] first4=0x{cyc:08x} "
                  f"{head.hex()}")


if __name__ == "__main__":
    main()

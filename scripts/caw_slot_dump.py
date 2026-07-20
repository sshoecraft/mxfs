#!/usr/bin/env python3
# Dump the MXFS CAW lock-slot table from a shared LUN.
#
# Usage: caw_slot_dump.py <device> [--offset N] [--type T] [--ag N] [--ino N]
#
# Default --offset is the lock-region start for the standard mkfs_mxfs
# layout with max_nodes=64 (disklock_offset 67117056 + 32768 HB region).
# Verify against dmesg "MXFS envelope v1: XFS data at offset X": the
# disklock region ends at X, so lock region = X - 65536*512.
#
# Prints every live (MXCW) and tombstone (MXDL) slot with decoded
# resource id, holder bitmaps and generation.  Use it to detect
# DUPLICATE live slots for one resource (split-brain mutual exclusion).

import argparse
import struct
import sys

SLOT_SIZE = 512
MAX_SLOTS = 65536
MAGIC_LIVE = 0x4D584357   # MXCW
MAGIC_TOMB = 0x4D58444C   # MXDL
LTYPE = {1: "INODE", 2: "EXTENT", 3: "AG", 4: "JOURNAL", 5: "SUPER"}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("device")
    ap.add_argument("--offset", type=int, default=67149824,
                    help="byte offset of lock-slot region")
    ap.add_argument("--type", type=int, default=0, help="filter lock type")
    ap.add_argument("--ag", type=int, default=-1, help="filter AG number")
    ap.add_argument("--ino", type=int, default=-1, help="filter inode number")
    ap.add_argument("--all", action="store_true", help="include tombstones")
    args = ap.parse_args()

    live = {}
    dupes = []
    with open(args.device, "rb") as f:
        f.seek(args.offset)
        data = f.read(MAX_SLOTS * SLOT_SIZE)

    nlive = ntomb = 0
    for idx in range(MAX_SLOTS):
        s = data[idx * SLOT_SIZE:(idx + 1) * SLOT_SIZE]
        magic, gen = struct.unpack_from("<II", s, 0)
        if magic == MAGIC_TOMB:
            ntomb += 1
            if not args.all:
                continue
        elif magic != MAGIC_LIVE:
            continue
        vol, ino, off, ag = struct.unpack_from("<QQQI", s, 8)
        ltype = s[36]
        hex_, hpw, hpr, hcw, hcr, waiters = struct.unpack_from("<6Q", s, 40)
        gmode, wmode = s[88], s[89]
        lastmod, yt, yset = struct.unpack_from("<3Q", s, 96)
        if args.type and ltype != args.type:
            continue
        if args.ag >= 0 and (ltype != 3 or ag != args.ag):
            continue
        if args.ino >= 0 and (ltype != 1 or ino != args.ino):
            continue
        tag = "LIVE" if magic == MAGIC_LIVE else "TOMB"
        if magic == MAGIC_LIVE:
            nlive += 1
            key = (vol, ltype, ino, off, ag)
            if key in live:
                dupes.append((live[key], idx, key))
            else:
                live[key] = idx
        print(f"slot={idx} {tag} gen={gen} vol={vol:#x} "
              f"type={LTYPE.get(ltype, ltype)} ino={ino} ag={ag} "
              f"hex={hex_:#x} hpr={hpr:#x} hpw={hpw:#x} hcw={hcw:#x} "
              f"hcr={hcr:#x} waiters={waiters:#x} gm={gmode} wm={wmode} "
              f"yt={yt:#x} lastmod={lastmod}")

    print(f"# live={nlive} tombstones={ntomb}", file=sys.stderr)
    for a, b, key in dupes:
        print(f"# DUPLICATE-RESOURCE slots {a} and {b}: vol={key[0]:#x} "
              f"type={LTYPE.get(key[1], key[1])} ino={key[2]} ag={key[4]}",
              file=sys.stderr)
    if dupes:
        sys.exit(2)


if __name__ == "__main__":
    main()

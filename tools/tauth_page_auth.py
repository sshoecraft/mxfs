#!/usr/bin/env python3
"""tauth_page_auth.py — histogram of the TCP authority ledger's page AUTHORITY
as it sits on the platter.

Reads the region straight from the block device (both shadow copies of every
page), keeps the copy with the higher commit seq among those whose header
magic and page_id are sane, and prints how many pages each
{auth_state, auth_node, authority_epoch, target_node, target_inc} tuple owns.
The page-selection rule is the store's (highest valid seq wins); the crc32c is
NOT checked here, so a torn copy with a plausible header could be miscounted —
this is a census tool for a quiescent LUN, not a repair tool.

Usage:  tauth_page_auth.py <dev> <base_bytes> [--pages N] [--page P ...] [--entries]
        base_bytes is the region base printed by P-TAUTH-LEDGER-OPEN
        (mxfs: tauth: P-TAUTH-LEDGER-OPEN ... base=<bytes>) or the super's
        tauth_offset from chk_mxfs -v.  --page prints one page's tuple;
        --entries adds that page's non-EMPTY records (exclusive holder
        node/incarnation, shared-holder slot bitmap).
Runs on a node (python3, read access to the device) or anywhere the LUN is
visible.  Layout: [region hdr A][region hdr B][3 control pages][pages copy A]
[pages copy B], 4 KiB each (mxfs_tauth_page_off in include/mxfs/mxfs_tauth.h).
"""
import argparse
import mmap
import os
import struct
import sys
from collections import Counter

PAGE = 4096


class DirectDev:
    """seek/read over an O_DIRECT descriptor.  A buffered read of the block
    device on a node whose mxfs module holds it open is served from the
    device's page cache, which the module's bio writes never update, so it
    returns the image cached at the first read for as long as the device
    stays open (measured 0.89.4 on the heartbeat table).  Offsets and sizes
    here are whole 4 KiB pages, which O_DIRECT accepts."""

    def __init__(self, path):
        self.fd = os.open(path, os.O_RDONLY | os.O_DIRECT)
        self.pos = 0

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        os.close(self.fd)
        return False

    def seek(self, off):
        if off % 512:
            raise ValueError("offset %d is not sector-aligned" % off)
        self.pos = off

    def read(self, n):
        n = (n + PAGE - 1) // PAGE * PAGE
        buf = mmap.mmap(-1, n)
        try:
            got = os.preadv(self.fd, [buf], self.pos)
            data = bytes(buf[:got])
        finally:
            buf.close()
        self.pos += got
        return data
REGION_MAGIC = 0x48545541
PAGE_MAGIC = 0x47504154
STATE = {0: "UNOWNED", 1: "ACTIVE", 2: "PREPARED"}


def region_npages(f, base):
    for copy in (0, 1):
        f.seek(base + copy * PAGE)
        hdr = f.read(PAGE)
        magic, _ver, _epp, npages = struct.unpack_from("<IHHI", hdr, 0)
        if magic == REGION_MAGIC and npages:
            return npages
    return 0


ENTRY_STATE = {0: "EMPTY", 1: "ACTIVE", 2: "FREE", 3: "UNKNOWN"}
HDR_BYTES = 128
ENTRY_BYTES = 128


def decode(buf, page_id):
    magic, _ver, _nent, pid = struct.unpack_from("<IHHI", buf, 0)
    if magic != PAGE_MAGIC or pid != page_id:
        return None
    seq, auth_epoch = struct.unpack_from("<QQ", buf, 16)
    auth_state = buf[96]
    auth_node, target_node = struct.unpack_from("<II", buf, 100)
    (target_inc,) = struct.unpack_from("<Q", buf, 112)
    return seq, (STATE.get(auth_state, str(auth_state)), auth_node, auth_epoch,
                 target_node, target_inc), buf


def entries(buf):
    """Every non-EMPTY record of one page (struct mxfs_tauth_entry, 128 B
    each after the 128 B header): state, resource, exclusive holder and the
    shared-holder slot bitmap.  The records a page still carries are what a
    later import installs — a departed incarnation's EX or a slot bit is a
    blocker until something retires it."""
    out = []
    n = (PAGE - HDR_BYTES) // ENTRY_BYTES
    for i in range(n):
        o = HDR_BYTES + i * ENTRY_BYTES
        state, res_type, shared_mode, ag = struct.unpack_from("<HBBI", buf, o)
        if state == 0:
            continue
        ino, _off, holders = struct.unpack_from("<QQQ", buf, o + 8)
        ex_node, ex_slot, ex_mode = struct.unpack_from("<IHB", buf, o + 40)
        (ex_inc,) = struct.unpack_from("<Q", buf, o + 48)
        slots = [s for s in range(64) if holders & (1 << s)]
        out.append("  ent[%d] %s type=%d ag=%d ino=%d ex=%d/%d slot=%d mode=%d "
                   "shared_mode=%d holders=%s" %
                   (i, ENTRY_STATE.get(state, str(state)), res_type, ag, ino,
                    ex_node, ex_inc, ex_slot, ex_mode, shared_mode, slots))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dev")
    ap.add_argument("base", type=int)
    ap.add_argument("--pages", type=int, default=0,
                    help="page count (default: from the region header)")
    ap.add_argument("--page", type=int, action="append", default=[],
                    help="print this page's tuple (repeatable)")
    ap.add_argument("--chunk", type=int, default=256, help="pages per read")
    ap.add_argument("--entries", action="store_true",
                    help="with --page: also list the page's non-EMPTY records")
    a = ap.parse_args()

    with DirectDev(a.dev) as f:
        npages = a.pages or region_npages(f, a.base)
        if not npages:
            print("no valid region header at base %d" % a.base, file=sys.stderr)
            return 2
        # mxfs_tauth_page_off: 2 header copies, then 3 control pages (view
        # slot A, view slot B, root), then copy A, then copy B.
        off_a = a.base + (2 + 3) * PAGE
        off_b = off_a + npages * PAGE
        hist = Counter()
        invalid = both_invalid = 0
        want = set(a.page)
        for start in range(0, npages, a.chunk):
            n = min(a.chunk, npages - start)
            f.seek(off_a + start * PAGE)
            ca = f.read(n * PAGE)
            f.seek(off_b + start * PAGE)
            cb = f.read(n * PAGE)
            for i in range(n):
                pid = start + i
                da = decode(ca[i * PAGE:(i + 1) * PAGE], pid)
                db = decode(cb[i * PAGE:(i + 1) * PAGE], pid)
                if da is None and db is None:
                    both_invalid += 1
                    continue
                if da is None or db is None:
                    invalid += 1
                best = max((d for d in (da, db) if d is not None),
                           key=lambda d: d[0])
                hist[best[1]] += 1
                if pid in want:
                    print("page %d seq=%d state=%s auth=%d/%d target=%d/%d" %
                          ((pid, best[0]) + best[1]))
                    if a.entries:
                        for line in entries(best[2]):
                            print(line)
        print("pages=%d one_copy_invalid=%d both_invalid=%d" %
              (npages, invalid, both_invalid))
        for tup, n in hist.most_common():
            print("%7d  state=%-8s auth=%u/%u target=%u/%u" % ((n,) + tup))
    return 0


if __name__ == "__main__":
    sys.exit(main())

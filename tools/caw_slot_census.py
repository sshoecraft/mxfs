#!/usr/bin/env python3
"""caw_slot_census.py -- read the CAW slot table straight out of a LUN image.

    tools/caw_slot_census.py <lun-image> [--scan-mib N] [--top N]

`tools/caw_slotdump` speaks SG_IO, so it only runs from an initiator (a test
node).  This reads the same table offline, from the backing file on the target
host (`~/disk.img` on clyde), which means a census costs no rig time,
takes no lock, writes nothing, and cannot disturb a running board.

## What it measures and why that is the question

`find_slot` binds a resource at `resource_hash_raw(res) % 65536` and LINEAR
PROBES forward (dlm/dlm_caw.c:3126).  A deleted slot becomes a TOMBSTONE
("MXDL", dlm/dlm_caw.h:33) which is explicitly *skip-but-continue* -- so
tombstones lengthen probe chains exactly the way they do in any open-addressed
table, and they are not reclaimed by the walk that passes them.

That matters because the walk is I/O.  Probes read up to MXFS_CAW_PROBE_SPAN
(16) contiguous slots per SCSI READ(16), so a chain of D slots costs about
ceil(D/16) round trips.  sess481 measured a contended unlock spending 9.42 ms
per attempt that is neither its counted backoff sleep nor the device service
time of a single slot operation (0.77-1.54 ms), and `find_slot` runs on EVERY
retry of that loop -- re-walking the chain even though the retry already holds
the slot index.  If displacement is large, that residue has a home.

So the numbers to read here are **load factor including tombstones** (the thing
that drives probe length) and **the displacement distribution** of live slots
from their computed home.  A table that is mostly tombstones behaves like a
nearly full table however few live entries it holds.

## Caveat, stated because it changes how you read the output

The image is served with `o_direct=1`, so what is on disk is what the fleet
wrote -- but this is a point-in-time read of a table the cluster is actively
mutating, and slots are not read atomically with respect to each other.  Treat
the distribution as a census, not as a consistent snapshot, and do not draw
conclusions from any single slot.
"""
import os
import struct
import sys

SLOT = 512
SLOTS = 65536
LIVE = 0x4D584357        # "MXCW"
TOMB = 0x4D58444C        # "MXDL"


def fnv1a(b):
    h = 2166136261
    for x in b:
        h ^= x
        h = (h * 16777619) & 0xFFFFFFFF
    return h


def home(volume, ino, offset, ag, rtype):
    return fnv1a(struct.pack("<QQQIB3x", volume, ino, offset, ag, rtype)) % SLOTS


def base_from_chk(img):
    """Ask chk_mxfs for the envelope layout.  lock_region_offset is
    disklock_offset + MXFS_DISKLOCK_HB_SIZE (64 records x 512 B), per
    dlm/dlm_caw.c:15522 and dlm/disklock.h:125-126.  This is exact, and unlike
    scanning for the magic it works on a table that is currently EMPTY --
    which is the normal state between runs, and is itself worth reporting."""
    import re
    import subprocess
    chk = os.path.join(os.path.dirname(os.path.abspath(__file__)), "chk_mxfs")
    if not os.path.exists(chk):
        return None
    try:
        out = subprocess.run([chk, "-v", img], capture_output=True, text=True,
                             timeout=180).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    m = re.search(r"disklock_offset=(\d+)", out)
    return (int(m.group(1)) + 64 * 512) if m else None


def find_base(fh, scan_mib):
    """Locate the slot table: the earliest 512-aligned magic that has a dense
    run of further magics within one table's length after it."""
    hits = []
    chunk = 8 << 20
    end = scan_mib << 20
    off = 0
    while off < end:
        fh.seek(off)
        buf = fh.read(chunk)
        if not buf:
            break
        for i in range(0, len(buf) - 4, SLOT):
            m = struct.unpack_from("<I", buf, i)[0]
            if m in (LIVE, TOMB):
                hits.append(off + i)
        off += chunk
    if not hits:
        return None, 0
    span = SLOTS * SLOT
    best, bestn = None, 0
    for h in hits:
        n = sum(1 for x in hits if h <= x < h + span)
        if n > bestn:
            best, bestn = h, n
    return best, bestn


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    opts = {a.split("=")[0]: (a.split("=")[1] if "=" in a else None)
            for a in sys.argv[1:] if a.startswith("--")}
    if not args:
        sys.exit(__doc__)
    img = args[0]
    scan_mib = int(opts.get("--scan-mib") or 512)
    topn = int(opts.get("--top") or 12)

    size = os.path.getsize(img)
    print("image %s (%.1f GiB)" % (img, size / (1 << 30)))
    base = None
    if opts.get("--base"):
        base = int(opts["--base"], 0)
        print("slot table base = 0x%x (given)" % base)
    if base is None:
        base = base_from_chk(img)
        if base is not None:
            print("slot table base = 0x%x (chk_mxfs disklock_offset + 32768)"
                  % base)
    with open(img, "rb") as fh:
        if base is None:
            base, n = find_base(fh, scan_mib)
            if base is None:
                sys.exit("could not locate the slot table: chk_mxfs did not "
                         "report disklock_offset and no CAW magic was found in "
                         "the first %d MiB. Pass --base=0x... " % scan_mib)
            print("slot table base = 0x%x (found by magic scan, %d slots)"
                  % (base, n))

        fh.seek(base)
        raw = fh.read(SLOTS * SLOT)
    if len(raw) < SLOTS * SLOT:
        print("WARNING: short read, only %d of %d slots" % (len(raw) // SLOT, SLOTS))

    live = tomb = empty = other = 0
    disp = []
    bytype = {}
    for i in range(len(raw) // SLOT):
        o = i * SLOT
        magic = struct.unpack_from("<I", raw, o)[0]
        if magic == TOMB:
            tomb += 1
            continue
        if magic != LIVE:
            if raw[o:o + 64] == b"\0" * 64:
                empty += 1
            else:
                other += 1
            continue
        live += 1
        vol, ino, roff = struct.unpack_from("<QQQ", raw, o + 8)
        ag, rtype = struct.unpack_from("<IB", raw, o + 32)
        bytype[rtype] = bytype.get(rtype, 0) + 1
        d = (i - home(vol, ino, roff, ag, rtype)) % SLOTS
        disp.append(d)

    used = live + tomb
    print("\n== occupancy ==")
    print("  live       %6d  (%.2f%%)" % (live, 100.0 * live / SLOTS))
    print("  tombstone  %6d  (%.2f%%)   <- skip-but-continue: these lengthen chains"
          % (tomb, 100.0 * tomb / SLOTS))
    print("  empty      %6d  (%.2f%%)   <- the only thing that TERMINATES a probe"
          % (empty, 100.0 * empty / SLOTS))
    if other:
        print("  unreadable %6d   (neither magic, not zeroed)" % other)
    print("  LOAD FACTOR (live+tombstone) = %.4f" % (used / float(SLOTS)))
    if bytype:
        names = {1: "INODE", 3: "AG", 6: "ICLUS"}
        print("  live by type: " + "  ".join(
            "%s=%d" % (names.get(t, "t%d" % t), c) for t, c in sorted(bytype.items())))

    if not disp:
        print("\nno live slots -- nothing to say about probe distance")
        return 0
    disp.sort()
    n = len(disp)
    at_home = sum(1 for d in disp if d == 0)
    print("\n== probe displacement of live slots from their computed home ==")
    print("  at home (0)  %6d  (%.1f%%)" % (at_home, 100.0 * at_home / n))
    for q, lbl in ((0.5, "p50"), (0.9, "p90"), (0.99, "p99")):
        print("  %-12s %6d" % (lbl, disp[min(n - 1, int(n * q))]))
    print("  max          %6d" % disp[-1])
    mean = sum(disp) / float(n)
    print("  mean         %9.2f" % mean)
    spans = sum((d // 16) + 1 for d in disp) / float(n)
    print("\n  implied span reads per successful lookup: %.2f "
          "(ceil(displacement/16), one SCSI READ(16) each)" % spans)
    print("  At 0.77-1.54 ms per slot round trip that is roughly %.1f-%.1f ms "
          "of I/O per find_slot call." % (spans * 0.77, spans * 1.54))
    print("  The unlock retry loop calls find_slot once PER RETRY "
          "(dlm/dlm_caw.c:10567), so multiply by 1+retries.")
    big = [d for d in disp if d >= 16]
    print("\n  live slots needing more than one span read: %d (%.1f%%)"
          % (len(big), 100.0 * len(big) / n))
    if big:
        big.sort(reverse=True)
        print("  worst displacements: %s" % " ".join(str(x) for x in big[:topn]))
    return 0


if __name__ == "__main__":
    sys.exit(main())

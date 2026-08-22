#!/usr/bin/env python3
"""caw_slot_hash.py — compute the CAW home slot of a resource, in userspace.

`find_slot` binds a resource at `resource_hash_raw(res) % 65536` and linear
probes forward past tombstones (dlm/dlm_caw.c:3126, 3187-3279).
`resource_hash_raw` (dlm/dlm_shared.c:34) is FNV-1a over the RAW BYTES of
`struct mxfs_resource_id` — seedless and endian-fixed, so it reproduces exactly
outside the kernel:

    struct mxfs_resource_id {        offset  size
        uint64_t volume;                 0     8
        uint64_t ino;                    8     8
        uint64_t offset;                16     8
        uint32_t ag_number;             24     4
        uint8_t  type;                  28     1
        uint8_t  pad[3];                29     3
    };                              total     32

Reproducing it is what makes the tombstone/slot-reuse hazard TESTABLE. Waiting
for random churn to re-bind a specific freed index is hopeless (~1/65536 per
acquisition), but a DIRECTED collision is cheap: enumerate real inode numbers
from the live filesystem, compute their home slots here, and pick a pair that
collides across the closure boundary. Nothing is forged — the pair are ordinary
resources the filesystem acquires through its normal paths.

Subcommands:
  home   <vol_hex> <type> <ino> <ag> [offset]   one resource's home slot
  verify <slotdump-capture>                     replicate every LIVE slot in a
                                                caw_slotdump --all capture and
                                                report how many sit at their
                                                computed home (or a short probe
                                                offset).  This is the proof the
                                                replication is exact.
  collide <slotdump-capture> <inolist> <shift>  find (A,B) inode pairs that share
                                                a home slot but live in
                                                DIFFERENT AGs.  `inolist` is
                                                "ino path" lines from stat.
  pick    <slotdump-capture> <inolist> <shift>  choose ONE usable pair for the
                                                directed reuse test and print
                                                "S inoA agA pathA inoB agB pathB".
                                                Usable means: the home slot is
                                                not currently LIVE, and neither
                                                inode is bound in any live slot,
                                                so A really will bind AT its home
                                                and B really will land there once
                                                A's slot is tombstoned.
Types: 1=INODE 3=AG 6=ICLUSTER (as logged by the kernel).
"""
import struct
import sys

SLOTS = 65536


def fnv1a(b):
    h = 2166136261
    for x in b:
        h ^= x
        h = (h * 16777619) & 0xFFFFFFFF
    return h


def res_bytes(volume, ino, offset, ag, rtype):
    return struct.pack("<QQQIB3x", volume, ino, offset, ag, rtype)


def home(volume, rtype, ino, ag, offset=0):
    return fnv1a(res_bytes(volume, ino, offset, ag, rtype)) % SLOTS


TYPE_NAME = {"INODE": 1, "AG": 3, "ICLUS": 6}


def parse_dump(path):
    """yield (slot, live, typename, vol, ag, ino) for each slot line."""
    import re
    for line in open(path):
        if not line.startswith("slot="):
            continue
        slot = int(re.search(r"^slot=(\d+)", line).group(1))
        live = " LIVE " in line
        tm = re.search(r"\btype=(\w+)", line)
        vm = re.search(r"\bvol=0x([0-9a-f]+)", line)
        am = re.search(r"\bag=(\d+)", line)
        im = re.search(r"\bino=(\d+)", line)
        yield (slot, live, tm.group(1) if tm else "?",
               int(vm.group(1), 16) if vm else 0,
               int(am.group(1)) if am else 0,
               int(im.group(1)) if im else 0)


def cmd_verify(path):
    ok = probed = miss = skipped = 0
    for slot, live, tname, vol, ag, ino in parse_dump(path):
        if not live or tname not in TYPE_NAME:
            skipped += 1
            continue
        h = home(vol, TYPE_NAME[tname], ino, ag)
        d = (slot - h) % SLOTS
        if d == 0:
            ok += 1
        elif d < 64:
            probed += 1
            print("probe+%d slot=%d home=%d type=%s ag=%d ino=%d" %
                  (d, slot, h, tname, ag, ino))
        else:
            miss += 1
            print("MISMATCH slot=%d home=%d type=%s ag=%d ino=%d" %
                  (slot, h, tname, ag, ino))
    print("verify: at-home=%d probe-offset=%d MISMATCH=%d skipped=%d" %
          (ok, probed, miss, skipped))
    return 1 if miss else 0


def cmd_collide(dumppath, inolist, shift):
    """Find inode pairs sharing a home slot but sitting in different AGs."""
    vol = 0
    for _, _, _, v, _, _ in parse_dump(dumppath):
        if v:
            vol = v
            break
    if not vol:
        sys.exit("could not read the volume id from the dump")
    buckets = {}
    for line in open(inolist):
        f = line.split()
        if len(f) < 2 or not f[0].isdigit():
            continue
        ino, path = int(f[0]), f[1]
        h = home(vol, 1, ino, 0)
        buckets.setdefault(h, []).append((ino, ino >> shift, path))
    found = 0
    for h, entries in sorted(buckets.items()):
        if len(entries) < 2:
            continue
        for i in range(len(entries)):
            for j in range(i + 1, len(entries)):
                a, b = entries[i], entries[j]
                if a[1] == b[1]:
                    continue          # same AG — no closure boundary to cross
                print("PAIR home=%d A ino=%d ag=%d %s | B ino=%d ag=%d %s" %
                      (h, a[0], a[1], a[2], b[0], b[1], b[2]))
                found += 1
    print("collide: vol=0x%016x candidates=%d cross-AG pairs=%d" %
          (vol, sum(len(v) for v in buckets.values()), found))
    return 0 if found else 1


def cmd_pick(dumppath, inolist, shift):
    """One pair that will actually behave as the test needs.

    The pair is useless unless A binds at the home slot ITSELF rather than at a
    probe offset, so the home slot must be free, and neither inode may already
    be bound elsewhere (a live binding does not migrate, so B could never land
    on the freed slot).  Both AGs must be non-zero: ag0 carries the root inode
    the blocked prober contends for and has to stay out of the forged domain.
    """
    vol = 0
    live_slots = set()
    live_inos = set()
    for slot, live, tname, v, ag, ino in parse_dump(dumppath):
        if v and not vol:
            vol = v
        if live:
            live_slots.add(slot)
            if ino:
                live_inos.add(ino)
    if not vol:
        sys.exit("could not read the volume id from the dump")
    buckets = {}
    for line in open(inolist):
        f = line.split()
        if len(f) < 2 or not f[0].isdigit():
            continue
        ino, path = int(f[0]), f[1]
        if ino in live_inos:
            continue
        buckets.setdefault(home(vol, 1, ino, 0), []).append((ino, ino >> shift, path))
    for h, entries in sorted(buckets.items()):
        if h in live_slots or len(entries) < 2:
            continue
        for i in range(len(entries)):
            for j in range(i + 1, len(entries)):
                a, b = entries[i], entries[j]
                if a[1] == b[1] or a[1] == 0 or b[1] == 0:
                    continue
                print("%d %d %d %s %d %d %s" %
                      (h, a[0], a[1], a[2], b[0], b[1], b[2]))
                return 0
    return 1


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    c = sys.argv[1]
    if c == "home":
        vol = int(sys.argv[2], 16)
        print(home(vol, int(sys.argv[3]), int(sys.argv[4]), int(sys.argv[5]),
                   int(sys.argv[6]) if len(sys.argv) > 6 else 0))
    elif c == "verify":
        sys.exit(cmd_verify(sys.argv[2]))
    elif c == "pick":
        sys.exit(cmd_pick(sys.argv[2], sys.argv[3], int(sys.argv[4])))
    elif c == "collide":
        sys.exit(cmd_collide(sys.argv[2], sys.argv[3], int(sys.argv[4])))
    else:
        sys.exit(__doc__)

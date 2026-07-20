#!/usr/bin/env python3
# caw_slot_sampler.py — high-rate time series of ONE CAW lock slot.
#
# Reads the slot's 512B sector with O_DIRECT from the SCST backing file on
# clyde (coherent with the initiators' o_direct writes) every ~1-2ms and
# prints a line whenever the slot content CHANGES.  Built for the sess6
# dlm_fairness monopoly investigation: shows holder churn vs waiter
# registration vs yield_to arming at CAS granularity.
#
# Usage: caw_slot_sampler.py <device> <ino> [--secs 20] [--offset 67149824]
import argparse, ctypes, os, struct, sys, time

SLOT_SIZE = 512
MAX_SLOTS = 65536
MAGIC_LIVE = 0x4D584357
MAGIC_TOMB = 0x4D58444C

def find_slot(dev, offset, ino, args_ltype=1):
    hits = []
    with open(dev, "rb") as f:
        f.seek(offset)
        data = f.read(MAX_SLOTS * SLOT_SIZE)
    for idx in range(MAX_SLOTS):
        s = data[idx*SLOT_SIZE:(idx+1)*SLOT_SIZE]
        magic = struct.unpack_from("<I", s, 0)[0]
        if magic not in (MAGIC_LIVE, MAGIC_TOMB):
            continue
        sino = struct.unpack_from("<Q", s, 16)[0]
        ltype = s[36]
        if ltype == args_ltype and sino == ino:
            hits.append((idx, magic))
    return hits

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("device"); ap.add_argument("ino", type=int)
    ap.add_argument("--secs", type=float, default=20.0)
    ap.add_argument("--offset", type=int, default=67149824)
    ap.add_argument("--ltype", type=int, default=1)
    args = ap.parse_args()

    hits = find_slot(args.device, args.offset, args.ino, args.ltype)
    if not hits:
        print(f"no slot for ino={args.ino}", file=sys.stderr); sys.exit(1)
    idx = hits[-1][0]
    print(f"# ino={args.ino} slot={idx} (candidates={hits})", file=sys.stderr)

    byte_off = args.offset + idx * SLOT_SIZE
    aligned = byte_off & ~4095
    skew = byte_off - aligned
    fd = os.open(args.device, os.O_RDONLY | os.O_DIRECT)
    buf = ctypes.create_string_buffer(8192)
    addr = ctypes.addressof(buf)
    abuf = (ctypes.c_char * 4096).from_address((addr + 4095) & ~4095)

    prev = None
    t_end = time.monotonic() + args.secs
    t0 = time.monotonic()
    nsamp = 0
    while time.monotonic() < t_end:
        n = os.preadv(fd, [abuf], aligned)
        s = bytes(abuf[skew:skew+SLOT_SIZE])
        nsamp += 1
        cur = s[:128]
        if cur != prev:
            magic, gen = struct.unpack_from("<II", s, 0)
            hex_, hpw, hpr, hcw, hcr, waiters = struct.unpack_from("<6Q", s, 40)
            gm, wm = s[88], s[89]
            streak = struct.unpack_from("<I", s, 92)[0]
            lastmod, yt, yset = struct.unpack_from("<3Q", s, 96)
            wex = struct.unpack_from("<Q", s, 120)[0]
            ts = (time.monotonic() - t0) * 1000
            wall = int(time.time() * 1000000)
            print(f"{ts:9.1f}ms wall={wall} gen={gen} hex={hex_:02x} hpr={hpr:02x} "
                  f"w={waiters:02x} wex={wex:02x} gm={gm} wm={wm} "
                  f"yt={yt:02x} yset={yset} streak={streak} "
                  f"{'LIVE' if magic==MAGIC_LIVE else 'TOMB' if magic==MAGIC_TOMB else hex(magic)}")
            prev = cur
        time.sleep(0.001)
    print(f"# samples={nsamp} over {args.secs}s", file=sys.stderr)
    os.close(fd)

if __name__ == "__main__":
    main()

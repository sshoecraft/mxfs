#!/usr/bin/env python3
"""Decode the buffer event ring a buffer diagnostic line carries.

mxfs_buf_diag_dump (pal/linux/xfs_buf.c) prints one line per stuck buffer
(P128-AILSTUCK-IBUF, P129-FLUSHING-BUF, P113-DRAIN-WEDGE-BUF, ...) ending in
`now_ms=N evi=N ev=[e0 ... e7]`: the last eight lifecycle events of that
buffer, oldest first, each a packed 64-bit word (mxfs_buf_ev):

    [63:60] event type     [59:44] b_flags & 0xffff   [43] a sync waiter
    [42] force_sync        [41:30] pid & 0xfff        [29:0] time, ~1.05 ms units

This prints, per distinct buffer (daddr) and tag, the first such line decoded:
each event's name, the low 16 flag bits as they were, the pid bits, and how
long before the dump it happened.  Nothing is printed raw.

    tools/bufring_decode.py KERNLOG.gz [--tag P129-FLUSHING-BUF] [--daddr N]
                            [--since HH:MM:SS] [--limit N]
"""
import argparse
import gzip
import re
import sys

NAMES = {1: "SUBMIT", 2: "BIOEND", 3: "IOEND", 4: "WORKER", 5: "EHERR", 6: "RESUB",
         7: "BIO", 8: "IOFAIL", 9: "IOWAIT", 10: "STALE", 0: "-"}
FLAGS = ((0, "READ"), (1, "WRITE"), (2, "RA"), (4, "ASYNC"), (5, "DONE"), (6, "STALE"),
         (7, "WRITE_FAIL"))
UNIT_MS = (1 << 20) / 1e6
LINE = re.compile(r"\[\w+ \w+ +\d+ (\d\d:\d\d:\d\d) \d+\] .*?mxfs: (\S+) (.*)$")
RING = re.compile(r"now_ms=(\d+) evi=(\d+) ev=\[([0-9a-f ]+)\]")


def flag_names(bits):
    names = [name for bit, name in FLAGS if bits & (1 << bit)]
    rest = bits & ~sum(1 << bit for bit, _ in FLAGS)
    if rest:
        names.append("0x%x" % rest)
    return "|".join(names) or "0"


def field(body, key):
    found = re.search(r"\b%s=(\S+)" % re.escape(key), body)
    return found.group(1) if found else "-"


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("kernlog")
    parser.add_argument("--tag", help="only lines with this tag (prefix match)")
    parser.add_argument("--daddr", help="only this buffer")
    parser.add_argument("--since", help="HH:MM:SS; lines stamped earlier are skipped")
    parser.add_argument("--limit", type=int, default=12, help="buffers printed (default 12)")
    args = parser.parse_args()

    seen = set()
    total = 0
    opener = gzip.open if args.kernlog.endswith(".gz") else open
    with opener(args.kernlog, "rt", errors="replace") as handle:
        for raw in handle:
            ring = RING.search(raw)
            if not ring:
                continue
            line = LINE.search(raw)
            if not line:
                continue
            stamp, tag, body = line.groups()
            if args.since and stamp < args.since:
                continue
            if args.tag and not tag.startswith(args.tag):
                continue
            daddr = field(body, "daddr")
            if args.daddr and daddr != args.daddr:
                continue
            total += 1
            if (tag, daddr) in seen:
                continue
            seen.add((tag, daddr))
            if len(seen) > args.limit:
                continue
            now = int(ring.group(1)) & 0x3fffffff
            print("%s %s ino=%s daddr=%s bflags=%s hold=%s nli=%s onlist=%s dwskip_n=%s "
                  "last_delwri_submit=%s"
                  % (stamp, tag, field(body, "ino"), daddr, field(body, "bflags"),
                     field(body, "hold"), field(body, "nli"), field(body, "onlist"),
                     field(body, "dwskip_n"),
                     "never" if field(body, "dwsub_ms") == "0" else
                     "%.0f ms before" % (((int(ring.group(1)) - int(field(body, "dwsub_ms")))
                                          & 0xffffffff) * UNIT_MS)))
            for word in ring.group(3).split():
                value = int(word, 16)
                if not value:
                    continue
                when = value & 0x3fffffff
                print("    %-7s flags=%-28s pid&0xfff=%-5d sync_waiter=%d %9.0f ms before"
                      % (NAMES.get(value >> 60, "?%d" % (value >> 60)),
                         flag_names((value >> 44) & 0xffff), (value >> 30) & 0xfff,
                         (value >> 43) & 1, ((now - when) & 0x3fffffff) * UNIT_MS))
    print("# lines with a ring: %d, distinct (tag, buffer): %d, printed: %d"
          % (total, len(seen), min(len(seen), args.limit)))
    return 0


if __name__ == "__main__":
    sys.exit(main())

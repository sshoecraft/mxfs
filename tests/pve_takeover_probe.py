#!/usr/bin/env python3
"""pve_takeover_probe.py <tree> <tag> — run on a survivor: a directory named
<tag> made in every probe directory of <tree> (an exclusive lock on that
directory) and every probe file in it stat'ed (a shared lock on the file),
each operation timed on its own.  The tree is one the dead peer wrote and this
host never touched, so every operation is a new lock request, and those whose
inode routes to a ledger page of the dead peer's meet that page's takeover.

Prints one OP line for every operation that failed or took longer than 1 s,
then one SUMMARY line: ops, failures, worst and median milliseconds, and the
worst operation.
"""
import os
import sys
import time


def timed(fn, *args):
    t = time.monotonic()
    try:
        fn(*args)
        err = ""
    except OSError as e:
        err = "%s(%d)" % (e.strerror, e.errno)
    return (time.monotonic() - t) * 1000.0, err


def main():
    if len(sys.argv) != 3:
        print("usage: pve_takeover_probe.py <tree> <tag>", file=sys.stderr)
        return 2
    tree, tag = sys.argv[1], sys.argv[2]
    lat = []
    fails = 0
    worst = (0.0, "")
    for d in sorted(os.listdir(tree)):
        dp = os.path.join(tree, d)
        if not os.path.isdir(dp):
            continue
        ops = [("mkdir", os.path.join(dp, tag), os.mkdir)]
        for f in sorted(os.listdir(dp)):
            if f != tag:
                ops.append(("stat", os.path.join(dp, f), os.stat))
        for name, path, fn in ops:
            ms, err = timed(fn, path)
            lat.append(ms)
            if err:
                fails += 1
            if ms > worst[0]:
                worst = (ms, "%s %s" % (name, path))
            if err or ms > 1000:
                print("OP %s %s ms=%.0f %s" % (name, path, ms, err or "ok"), flush=True)
    lat.sort()
    med = lat[len(lat) // 2] if lat else 0.0
    print("SUMMARY ops=%d failures=%d worst_ms=%.0f median_ms=%.1f worst_op=%s" %
          (len(lat), fails, worst[0], med, worst[1] or "-"))
    return 0


if __name__ == "__main__":
    sys.exit(main())

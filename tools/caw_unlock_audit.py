#!/usr/bin/env python3
"""caw_unlock_audit.py -- where a contended CAW unlock's wall time goes.

    tools/caw_unlock_audit.py <evidence-dir-or-kernlog>...
    tools/caw_unlock_audit.py --compare <dir-A> -- <dir-B>

Harvests `mxfs: P381-UNLK-CONTEND` (dlm/dlm_caw.c, sess380) out of node kernel
logs and accounts for the wall time of a contended unlock.

## The trap this tool exists to not repeat

The probe originally reported only `retries`, `miscmp`, `sleep_ms` and
`wall_ms`.  On a 32-node crash_consistency row (17,558 contended unlocks) that
gave mean wall 35.1 ms against mean sleep 9.3 ms, and it is very tempting to
call the remaining 25.8 ms "slot I/O" and divide it by attempts to get a
round-trip cost.  sess481 did exactly that, got 9.42 ms per attempt, and wrote
it into a defect record as the root cause.

**It was wrong.**  The same run's DIRECT service-time probes say a slot read
costs **0.77 ms mean** (p50 1, p90 2, max 32) -- `P297-TKT`'s `read_ms`, which is
a PER-READ value -- and `P138-AGWAIT`'s `caw_svc_ms` averages 1.54 ms.  So the
device is roughly an order of magnitude cheaper than the 9.42 ms residue, and
`wall - sleep` was never "slot I/O": it was *unaccounted*.

A SECOND derivation error, caught the same session and worth stating because it
is easy to repeat: `read_ms` is ASSIGNED per poll (`dlm/dlm_caw.c:6908`), i.e.
the LAST read's duration, while `reads` is CUMULATIVE.  Dividing sum(read_ms) by
sum(reads) across samples mixes the two and yields a number that means nothing
(it gave a spurious 0.22 ms).  **Check whether a probe field is cumulative or
last-value before dividing by anything.**  0.65.0 adds `read_sum_ms=` and
`sleep_sum_ms=` to `P297-TKT` so a wait's totals can be stated, not inferred.

Two things in the unlock retry loop were unmeasured, and sess481 added a field
for each:

    find_ms     time in find_slot, which re-walks the resource's hash chain in
                MXFS_CAW_PROBE_SPAN(16)-slot span reads on EVERY retry, even
                though a retry already knows slot_idx from the last iteration
    backoff_ms  time in caw_inode_backoff, which sleeps WITHOUT being added to
                sleep_ms (and returns early below retry 2, so it cannot explain
                a median gap where retries=1)

`unaccounted_ms` = wall - sleep - find - backoff is printed explicitly and is
the honest residue.  A large residue means the decomposition has not found the
cost yet; that is a finding, not a null result, and it says where to put the
next boundary.  Logs from a build older than 0.65.0 carry no find_ms/backoff_ms,
so the whole non-sleep term shows as unaccounted -- which is exactly what it was.

## The cause histogram

`multigen` dominating means the slot's generation moved between the read and the
compare-and-write.  Do NOT read that as "version the fields separately": one
slot is exactly one 512-byte sector (`_Static_assert` in dlm/dlm_caw.h), which
is the granularity of the SCSI COMPARE-AND-WRITE, so the compare covers every
peer's waiter bit however the struct is versioned.

## --compare

Prints two runs side by side, which is the shape the fastpoll A/B needs: if
unloading the device queue moves the per-attempt numbers, the poll storm was
inflating them.
"""
import gzip
import os
import re
import sys

TAG = "P381-UNLK-CONTEND"
KV = re.compile(r"(\w+)=(-?\d+)")
CAUSES = ["contended", "multigen", "holders", "benign", "noreg",
          "fast", "ident", "selfbits", "removed", "yieldto", "control"]


def opener(path):
    if path.endswith(".gz"):
        return gzip.open(path, "rt", errors="replace")
    return open(path, "r", errors="replace")


def expand(arg):
    if not os.path.isdir(arg):
        return [arg]
    return [os.path.join(arg, n) for n in sorted(os.listdir(arg))
            if n.startswith("kernlog_") or n.endswith(".gz")]


def collect(paths):
    rows, read, hit = [], 0, 0
    for p in paths:
        try:
            with opener(p) as f:
                read += 1
                n0 = len(rows)
                for ln in f:
                    if TAG not in ln:
                        continue
                    d = {k: int(v) for k, v in KV.findall(ln.split(TAG, 1)[1])}
                    if "wall_ms" in d:
                        rows.append(d)
                if len(rows) > n0:
                    hit += 1
        except OSError as e:
            print("  (unreadable: %s: %s)" % (p, e), file=sys.stderr)
    return rows, read, hit


def stats(vals):
    v = sorted(vals)
    if not v:
        return None
    return (len(v), sum(v), sum(v) / float(len(v)),
            v[len(v) // 2], v[int(len(v) * 0.9)], v[-1])


def summarise(label, rows, node_seconds=None):
    print("== %s ==" % label)
    if not rows:
        print("   NO %s LINES. The probe fires only on a CONTENDED unlock, so "
              "zero rows means no contention OR no capture -- it is not "
              "evidence of a fast unlock." % TAG)
        return None

    have_new = any("find_ms" in r for r in rows)
    fields = ["retries", "miscmp", "sleep_ms"]
    if have_new:
        fields += ["find_ms", "backoff_ms"]
    fields += ["wall_ms"]
    print("   %-14s %8s %10s %9s %7s %7s %7s"
          % ("field", "n", "sum", "mean", "p50", "p90", "max"))
    for f in fields:
        s = stats([r.get(f, 0) for r in rows])
        if s:
            print("   %-14s %8d %10d %9.1f %7d %7d %7d" % ((f,) + s))

    wall = sum(r.get("wall_ms", 0) for r in rows)
    sleep = sum(r.get("sleep_ms", 0) for r in rows)
    find = sum(r.get("find_ms", 0) for r in rows)
    back = sum(r.get("backoff_ms", 0) for r in rows)
    attempts = sum(1 + r.get("retries", 0) for r in rows)
    resid = wall - sleep - find - back

    def pc(x):
        return 100.0 * x / wall if wall else 0.0

    print("   -- accounting for %d ms of unlock wall over %d attempts --"
          % (wall, attempts))
    print("   counted backoff sleep : %9d ms  (%5.1f%%)" % (sleep, pc(sleep)))
    if have_new:
        print("   find_slot (chain walk): %9d ms  (%5.1f%%)  %.2f ms/attempt"
              % (find, pc(find), find / float(attempts) if attempts else 0))
        print("   caw_inode_backoff     : %9d ms  (%5.1f%%)" % (back, pc(back)))
    else:
        print("   find_slot / inode-backoff: NOT INSTRUMENTED in this build "
              "(pre-0.65.0) -- both fall into the residue below")
    print("   UNACCOUNTED           : %9d ms  (%5.1f%%)  %.2f ms/attempt"
          % (resid, pc(resid), resid / float(attempts) if attempts else 0))

    # The aggregate per-attempt figure is INFLATED and must not be quoted alone.
    # The residue is super-linear in retries (sess481: 5.4, 8.9, 12.5, 16.7,
    # 18.1, 19.8 ms/attempt at retries 1..6), and the reason is largely
    # selection: an unlock that needs many retries is one happening inside a
    # heavy burst, when the device, the scheduler and every mutex are slower.
    # Measured on the same run, mean concurrent P381 events in the same second
    # on the same node rose 31.5 -> 63.3 across retries 1 -> 5.  So the
    # least-contended bucket is the cleanest estimate of the per-attempt cost.
    low = [r for r in rows if r.get("retries", 0) == 1]
    if len(low) >= 20:
        lw = sum(r["wall_ms"] for r in low)
        ls = sum(r.get("sleep_ms", 0) for r in low)
        lf = sum(r.get("find_ms", 0) for r in low)
        lb = sum(r.get("backoff_ms", 0) for r in low)
        lr = lw - ls - lf - lb
        print("   LOW-CONTENTION FLOOR (retries=1, n=%d): %.2f ms unaccounted "
              "per attempt" % (len(low), lr / float(2 * len(low))))
        print("     Quote THIS as the per-attempt cost, not the aggregate above:"
              " the aggregate is dragged up by a burst-correlated tail.")
        print("     Note caw_inode_backoff is skipped below retry 2 "
              "(dlm/dlm_caw.c:8097), so this bucket carries none of it.")
    print("   NOTE: the residue is NOT slot I/O. On the sess481 baseline a slot"
          " read costs 0.77 ms mean (P297-TKT read_ms, a PER-READ value -- do"
          " NOT divide it by the cumulative reads count). Cross-check against a"
          " direct probe before attributing any of this to the LUN.")
    if node_seconds:
        print("   share of run: %.1f%% of %d node-seconds inside contended "
              "unlocks" % (100.0 * (wall / 1000.0) / node_seconds, node_seconds))

    tot = sum(sum(r.get(c, 0) for r in rows) for c in CAUSES)
    print("   miscompare causes:")
    for c in CAUSES:
        s = sum(r.get(c, 0) for r in rows)
        if s:
            print("     %-10s %8d  (%5.1f%%)" % (c, s, 100.0 * s / tot if tot else 0))
    zero = [c for c in CAUSES if not sum(r.get(c, 0) for r in rows)]
    if zero:
        print("     zero across every sample: %s" % " ".join(zero))
    print()
    return dict(wall=wall, resid=resid, find=find, attempts=attempts,
                per_resid=resid / float(attempts) if attempts else 0.0,
                per_find=find / float(attempts) if attempts else 0.0)


def main():
    args = sys.argv[1:]
    if not args:
        sys.exit(__doc__)

    if args[0] == "--compare":
        if "--" not in args:
            sys.exit("usage: --compare <dir-A> -- <dir-B>")
        cut = args.index("--")
        groups = (args[1:cut], args[cut + 1:])
        res = []
        for tag, g in zip("AB", groups):
            rows, read, hit = collect([p for a in g for p in expand(a)])
            print("read %d file(s), %d carried %s" % (read, hit, TAG))
            res.append(summarise("%s: %s" % (tag, " ".join(g)), rows))
        if all(res):
            for name, key in (("find_slot", "per_find"),
                              ("unaccounted", "per_resid")):
                a, b = res[0][key], res[1][key]
                d = (100.0 * (b - a) / a) if a else 0.0
                print("PER-ATTEMPT %-12s A %.2f ms -> B %.2f ms (%+.1f%%)"
                      % (name, a, b, d))
        return 0

    paths = [p for a in args for p in expand(a)]
    if not paths:
        sys.exit("no kernel logs found in: %s" % " ".join(args))
    rows, read, hit = collect(paths)
    print("read %d file(s), %d carried %s" % (read, hit, TAG))
    if read and not hit:
        print("REFUSING TO REPORT: not one input carried the probe.")
        return 2
    summarise("contended CAW unlocks", rows,
              node_seconds=read * 90 if read >= 8 else None)
    return 0


if __name__ == "__main__":
    sys.exit(main())

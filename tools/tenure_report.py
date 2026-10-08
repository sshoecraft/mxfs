#!/usr/bin/env python3
"""tenure_report.py — per host, how long each EX tenure of an inode lock was
held and how many operations it served, from the lock-tenure probes a churn
run collected (tests/pve_churn_fairness.sh PROBES=1).

Usage: tools/tenure_report.py <evidence dir> <shared dir inode> <host> [<host>...]
Reads <evidence dir>/klog.<host> (the host's kernel lines after the run's mark).

Lines read (dynamic-debug probes):
  P70-BP ino=N ENTRY ... held_ms=H tops=T fo_ms=F lo_ms=L ...
      one per release: H = grant to release entry, T = operations the tenure
      served, F = grant to its first op, L = its last op to release entry
  P483-DIRTENURE parent=N ... creates=C wall_ms=W mean_ms=M gap_ms=G ...
      one per directory tenure (emitted by the next tenure's first create)
  P6-FAIRQ site=local|remote ... wage_ms=A ...
      a request queued at the master behind an older conflicting waiter
  P-EX-TENURE-CAP
      the directory tenure cap closed the fast path
  P7S-BAST-FIRE ino=N target=T / P7B-BASTNOTIFY ino=N
      for dbg_probe_ino only: the master firing a BAST at holder T, and a
      holder receiving one; the host that fires is the lock's master
"""
import collections
import re
import sys

KV = re.compile(r"(\w+)=(\S+)")


def kv(line):
    return {k: v for k, v in KV.findall(line)}


def pct(v, p):
    v = sorted(v)
    return v[min(len(v) - 1, int(len(v) * p))] if v else 0


def num(d, k):
    try:
        return int(d.get(k, "0"))
    except ValueError:
        return 0


def summary(label, rel):
    if not rel:
        return f"    {label}: no release"
    held = [num(r, "held_ms") for r in rel]
    tops = [num(r, "tops") for r in rel]
    fo = [num(r, "fo_ms") for r in rel]
    lo = [num(r, "lo_ms") for r in rel]
    return (f"    {label}: releases={len(rel)} held_ms p50={pct(held, .5)} p90={pct(held, .9)} max={max(held)} "
            f"sum={sum(held)} | ops/tenure p50={pct(tops, .5)} p90={pct(tops, .9)} sum={sum(tops)} | "
            f"first-op p50={pct(fo, .5)} ms | last-op-to-release p50={pct(lo, .5)} p90={pct(lo, .9)} ms")


def main():
    if len(sys.argv) < 4:
        print(__doc__)
        return 2
    evid, dirino, hosts = sys.argv[1], sys.argv[2], sys.argv[3:]
    print(f"lock tenures (shared directory inode {dirino}):")
    for h in hosts:
        try:
            lines = open(f"{evid}/klog.{h}", errors="replace").read().splitlines()
        except OSError as e:
            print(f"  {h}: no kernel lines ({e})")
            continue
        rel = collections.defaultdict(list)
        dt, fq, cap = [], collections.defaultdict(list), 0
        fired, notified = collections.Counter(), 0
        for line in lines:
            if "P7S-BAST-FIRE" in line:
                d = kv(line)
                if d.get("ino") == dirino:
                    fired[d.get("target", "?")] += 1
            elif "P7B-BASTNOTIFY" in line:
                if kv(line).get("ino") == dirino:
                    notified += 1
            elif "P70-BP" in line and " ENTRY " in line:
                d = kv(line)
                rel[d.get("ino", "?")].append(d)
            elif "P483-DIRTENURE" in line:
                d = kv(line)
                if d.get("parent") == dirino:
                    dt.append(d)
            elif "P6-FAIRQ" in line:
                d = kv(line)
                fq[d.get("site", "?")].append(num(d, "wage_ms"))
            elif "P-EX-TENURE-CAP" in line:
                cap += 1
        files = [r for ino, rs in rel.items() if ino != dirino for r in rs]
        print(f"  {h}: {len(lines)} lines, P70-BP releases {sum(len(v) for v in rel.values())} over {len(rel)} inodes")
        print(summary(f"directory {dirino}", rel.get(dirino, [])))
        print(summary("every other inode", files))
        top = sorted(((len(v), ino) for ino, v in rel.items() if ino != dirino), reverse=True)[:5]
        for n, ino in top:
            print(summary(f"inode {ino}", rel[ino]))
        if dt:
            cr = [num(d, "creates") for d in dt]
            wall = [num(d, "wall_ms") for d in dt]
            gap = [num(d, "gap_ms") for d in dt]
            print(f"    directory tenures (P483): {len(dt)}, creates/tenure p50={pct(cr, .5)} p90={pct(cr, .9)} "
                  f"sum={sum(cr)}, wall_ms p50={pct(wall, .5)}, gap to next tenure p50={pct(gap, .5)} p90={pct(gap, .9)} ms")
        for site, ages in sorted(fq.items()):
            print(f"    queued behind an older waiter at the master (P6-FAIRQ site={site}): {len(ages)}, "
                  f"waiter age p50={pct(ages, .5)} p90={pct(ages, .9)} max={max(ages)} ms")
        print(f"    directory tenure cap closings (P-EX-TENURE-CAP): {cap}")
        # the master fires every BAST for the lock; the holder is notified
        print(f"    directory BASTs fired as master (P7S): {sum(fired.values())}"
              f" (targets {dict(fired)}); received as holder (P7B): {notified}"
              + ("  => this host masters the directory lock" if fired else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())

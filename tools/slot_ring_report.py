#!/usr/bin/env python3
"""Read the inode-slot write records of a DRBD pair run.

tests/pve_cluster_write_authority.sh leaves, per host, ring.<host> (the
module's slot record, mxfs.slot_ring: every inode slot an inode-cluster write
sent to the device, with the class it went out under and the in-core inode's
lock mode, generation and flags) and klog.<host> (the window's kernel lines,
`journalctl -o short-unix`).  This reports, from those files:

  census     per host: slots written, by class (L logged, B buffer-logged,
             R recovery-owned, W whole-buffer write, A allocation buffer,
             I in core) and lock mode; the slots of freshly initialised
             chunks (alloc_init); and the unlogged slots written
             ("passengers"), with those of a poisoned shell, held at a mode
             other than EX, not in core, or of another incarnation than the in-core inode
  conflicts  for each DRBD 'Concurrent writes detected' line, each host's last
             write of each sector it names, at or before the conflict (the
             other host's up to SLACK seconds after: two clocks)
  near       for each sector both hosts wrote, the cross-host pairs of writes
             closer together than WINDOW seconds, by the classes of the two:
             an overlap DRBD did not catch is one of these, and a passenger
             in one of them is a write this node had nothing of its own in
  crossings  the writes that put a dead incarnation on the device, from the
             slot images alone (the in-core generation is not used: a
             cluster write's igen is whichever in-core inode the cache
             returns, a stale corpse as often as the live one):
               resurrect  a live image of generation G written after a free
                          image of G (generation G+1, mode 0) went out for
                          that slot, by either host: a freed incarnation is
                          never live again
               overwrite  a live image of G written by one host when the
                          slot's previous write was the other host's live
                          image of a different generation, with no free image
                          between: the peer's allocation needs the free
                          published first, so the writer's image is stale
             a cross-host order is believed only when the two writes are more
             than SLACK apart (two clocks); same-host order is exact
  disklive   for each P-DIALLOC-DISKLIVE line (an allocator found a free
             number's home holding a live dinode), every slot record of that
             number from both hosts in time order up to the verdict: the
             write that put the live image there, and whether a free image
             went out before it

usage: tools/slot_ring_report.py <evidence dir> <host> <host> [WINDOW] [SLACK]
       WINDOW defaults to 0.02 s, SLACK to 0.5 s
"""

import collections
import re
import sys

REC = re.compile(r"^seq=(\d+) realns=(\d+) dsect=(\d+) ino=(\d+) gen=(\d+) mode=(\S+) "
                 r"cc=(\d+) cls=(\S+) dlm=(-?\d+) igen=(\d+) iflags=(\S+) stale=(\d) "
                 r"pid=(\d+) comm=(.*)$")
CONF = re.compile(r"Concurrent writes detected: local=(\d+)s \+(\d+), remote=(\d+)s \+(\d+)")
DISKLIVE = re.compile(r"P-DIALLOC-DISKLIVE ino=(\d+) \S+ \S+ disk_mode=(\S+) disk_gen=(\d+)")


def records(path):
    out = []
    try:
        fh = open(path, errors="replace")
    except OSError:
        return out
    with fh:
        for ln in fh:
            m = REC.match(ln.strip())
            if not m:
                continue
            out.append({
                "t": int(m.group(2)) / 1e9, "sect": int(m.group(3)), "ino": int(m.group(4)),
                "gen": int(m.group(5)), "mode": m.group(6), "cc": int(m.group(7)),
                "cls": m.group(8), "dlm": int(m.group(9)), "igen": int(m.group(10)),
                "stale": m.group(12) == "1", "comm": m.group(14), "line": ln.strip()})
    return out


def passenger(r):
    """An unlogged slot written: not logged, buffer-logged or recovery-owned,
    and not part of a freshly initialised inode chunk (a whole write of an
    allocation buffer, which must reach the device whole)."""
    return not any(c in r["cls"] for c in "LBRA")


def short(r):
    return ("%s ino=%d gen=%d mode=%s cc=%d cls=%s dlm=%d igen=%d stale=%d comm=%s"
            % (r["sect"], r["ino"], r["gen"], r["mode"], r["cc"], r["cls"], r["dlm"],
               r["igen"], r["stale"], r["comm"]))


def main():
    if len(sys.argv) < 4:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    evid, hosts = sys.argv[1], sys.argv[2:4]
    window = float(sys.argv[4]) if len(sys.argv) > 4 else 0.02
    slack = float(sys.argv[5]) if len(sys.argv) > 5 else 0.5
    ring = {h: records("%s/ring.%s" % (evid, h)) for h in hosts}

    for h in hosts:
        rs = ring[h]
        by = collections.Counter((r["cls"], r["dlm"]) for r in rs)
        cen = collections.Counter()
        ex = collections.defaultdict(list)
        for r in rs:
            if "A" in r["cls"]:
                cen["alloc_init"] += 1
            if not passenger(r):
                continue
            cen["passenger"] += 1
            for k, hit in (("poisoned", r["stale"]), ("not_ex", r["dlm"] not in (-1, 5)),
                           ("no_incore", r["dlm"] == -1),
                           ("other_incarnation", "I" in r["cls"] and r["gen"] != r["igen"])):
                if hit:
                    cen[k] += 1
                    ex[k].append(r)
        span = (max(r["t"] for r in rs) - min(r["t"] for r in rs)) if rs else 0
        print("%s census: %d slots written over %.1f s; by class/mode %s; passengers %s"
              % (h, len(rs), span, dict(by.most_common()), dict(cen)))
        for k, v in ex.items():
            for r in v[:4]:
                print("   %s: %s" % (k, short(r)))

    persect = {h: collections.defaultdict(list) for h in hosts}
    for h in hosts:
        for r in ring[h]:
            persect[h][r["sect"]].append(r)

    def last_write(h, sect, t, after):
        hits = [r for r in persect[h].get(sect, []) if r["t"] <= t + after]
        return hits[-1] if hits else None

    nconf = 0
    for h in hosts:
        other = [x for x in hosts if x != h][0]
        try:
            lines = open("%s/klog.%s" % (evid, h), errors="replace").read().splitlines()
        except OSError:
            lines = []
        for ln in lines:
            m = CONF.search(ln)
            if not m:
                continue
            nconf += 1
            if nconf > 16:
                continue
            try:
                t = float(ln.split(" ", 1)[0])
            except ValueError:
                continue
            ls, ln_, rs_, rn = (int(m.group(1)), int(m.group(2)) // 512,
                                int(m.group(3)), int(m.group(4)) // 512)
            print("conflict logged by %s at %.6f: local %d+%d remote %d+%d"
                  % (h, t, ls, ln_, rs_, rn))
            for who, base, cnt, after in ((h, ls, ln_, 0.0), (other, rs_, rn, slack)):
                for s in range(base, base + cnt):
                    r = last_write(who, s, t, after)
                    print("   %s %s" % (who, ("%+.4fs %s" % (r["t"] - t, short(r))) if r
                                         else "%d no record" % s))
    print("conflicts: %d" % nconf)

    # the pairs with a passenger in them are listed first, closest first
    near = collections.Counter()
    gap = {}
    pairs = []
    both = set(persect[hosts[0]]) & set(persect[hosts[1]])
    for s in sorted(both):
        ev = sorted([(r["t"], h, r) for h in hosts for r in persect[h][s]],
                    key=lambda x: x[0])
        for (t1, h1, r1), (t2, h2, r2) in zip(ev, ev[1:]):
            if h1 == h2 or t2 - t1 > window:
                continue
            k = ("P" if passenger(r1) else r1["cls"], "P" if passenger(r2) else r2["cls"])
            near[k] += 1
            gap[k] = min(gap.get(k, window), t2 - t1)
            pairs.append((not (passenger(r1) or passenger(r2)), t2 - t1, h1, r1, h2, r2))
    for _, d, h1, r1, h2, r2 in sorted(pairs, key=lambda p: (p[0], p[1]))[:12]:
        print("   near %.4fs: %s %s  then  %s %s" % (d, h1, short(r1), h2, short(r2)))
    print("near-misses within %.3f s on %d sectors both hosts wrote: %s; closest per pair %s"
          % (window, len(both), dict(near.most_common()),
             {"%s>%s" % k: round(v, 4) for k, v in sorted(gap.items())}))

    def live(r):
        return r["mode"] not in ("0", "00")

    cross = collections.Counter()
    cross_inos = collections.defaultdict(set)
    shown = 0
    allsect = set(persect[hosts[0]]) | set(persect[hosts[1]])
    for s in sorted(allsect):
        ev = sorted([(r["t"], h, r) for h in hosts for r in persect[h].get(s, [])],
                    key=lambda x: x[0])
        freed = {}      # generation G -> (t, host) of the first free image of G
        for i, (t, h, r) in enumerate(ev):
            if not live(r):
                g = (r["gen"] - 1) & 0xffffffff
                freed.setdefault(g, (t, h))
                continue
            kind = None
            f = freed.get(r["gen"])
            if f and (f[1] == h or t - f[0] > slack):
                kind = "resurrect"
            elif i:
                pt, ph, pr = ev[i - 1]
                if ph != h and live(pr) and pr["gen"] != r["gen"] and t - pt > slack:
                    kind = "overwrite"
            if not kind:
                continue
            cross[(h, kind)] += 1
            cross_inos[(h, kind)].add(r["ino"])
            if shown < 12:
                shown += 1
                print("   %s on %s: %s" % (kind, h, short(r)))
                for tt, hh, rr in ev[max(0, i - 3):i]:
                    print("      %+.4fs %s %s" % (tt - t, hh, short(rr)))
    print("crossings: %s" % ({"%s %s" % k: "%d writes, %d inodes" % (v, len(cross_inos[k]))
                              for k, v in sorted(cross.items())} or "none"))

    perino = collections.defaultdict(list)
    for h in hosts:
        for r in ring[h]:
            perino[r["ino"]].append((r["t"], h, r))
    for h in hosts:
        try:
            lines = open("%s/klog.%s" % (evid, h), errors="replace").read().splitlines()
        except OSError:
            lines = []
        for ln in lines:
            m = DISKLIVE.search(ln)
            if not m:
                continue
            try:
                t = float(ln.split(" ", 1)[0])
            except ValueError:
                continue
            ino, dmode, dgen = int(m.group(1)), m.group(2), int(m.group(3))
            ev = sorted(perino.get(ino, []), key=lambda x: x[0])
            upto = [e for e in ev if e[0] <= t + slack]
            print("disklive on %s at %.6f: ino=%d disk_mode=%s disk_gen=%d; %d slot records of it in the window, %d up to the verdict"
                  % (h, t, ino, dmode, dgen, len(ev), len(upto)))
            for tt, hh, r in upto[-24:]:
                mark = ""
                if r["gen"] == dgen and r["mode"] not in ("0", "00"):
                    mark = "  <== the live image found"
                elif r["mode"] in ("0", "00"):
                    mark = "  (free image)"
                print("   %+.4fs %s %s%s" % (tt - t, hh, short(r), mark))
    return 0


if __name__ == "__main__":
    sys.exit(main())

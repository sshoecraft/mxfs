#!/usr/bin/env python3
"""Digest the per-node kernel logs of one board run directory.

A run directory (tests/evidence/run_<row>_<runid>) holds one
kernlog_<node>.gz per node: `dmesg -T` output, so every line starts with a
wall-clock stamp "[Mon Sep 28 22:30:10 2026]" in the node's own time zone
(UTC on the rig).  The logs carry tens of thousands of probe lines per node;
this prints what a reader needs from them and nothing else:

  counts     per node, how often each probe tag fired inside the window
  timeline   the lines that match, merged across nodes in time order, each
             reduced to its tag and the key=value fields asked for

Nothing is printed raw: a line is its time, its node, its tag and a field
list, cut to --width.  Tags are the module's probe names (P-TAUTH-ACTIVATE,
P34-ACQ-SLOW, ...) plus the few untagged shapes named in SHAPES below.

    tools/kernlog_digest.py RUN_DIR counts [--tags T1,T2] [--min N]
    tools/kernlog_digest.py RUN_DIR timeline --match 'ino=128\\b|page=235\\b'
    tools/kernlog_digest.py RUN_DIR timeline --tags P-LKTIMEOUT-REMOTE --limit 40
    tools/kernlog_digest.py RUN_DIR mounts
    tools/kernlog_digest.py RUN_DIR imports --since 2026-09-29T04:10:00

imports classes the holders a ledger page import installed
(P-TAUTH-IMPORT-ACTIVE) by who each one names: `member` is a node mounted
in the window (its id is in a 'DLM init: node_id=' line of some node's log),
`unknown` is a record whose slot named no node, `departed` is every other
id: a holder no mounted node answers for.  One IMPORTS line per node, counts
only, split by lock mode; the retirements made instead
(P-TAUTH-IMPORT-RETIRE-*, P-TAUTH-IMPORT-RESIDUE*, P-TAUTH-SETTLED-*, the
last split by how the holder's tenancy had ended) are counted beside them.

The window defaults to the run id's own time (the directory name) onwards;
--since/--until take HH:MM:SS on the run's date, or a full
YYYY-MM-DDTHH:MM:SS.  --tz-hours adds that many hours to every stamp, for a
node whose clock is not UTC.
"""
import argparse
import collections
import datetime
import glob
import gzip
import os
import re
import sys

STAMP = re.compile(r"^\[\w{3} (\w{3}) +(\d+) (\d\d):(\d\d):(\d\d) (\d{4})\] ?")
MONTHS = {m: i + 1 for i, m in enumerate(
    "Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split())}
TAG = re.compile(r"\b(P[0-9A-Za-z]*-[A-Z0-9][A-Z0-9-]*[A-Z0-9])\b")
RUNID = re.compile(r"(\d{8})T(\d{6})Z")
FIELD = re.compile(r"\b([a-z_]+)=(\{[^}]*\}|[^ ,;()]+)")

# untagged line shapes worth a name of their own
SHAPES = [
    (re.compile(r"Mounting V\d+ Filesystem"), "MOUNT-BEGIN"),
    (re.compile(r"Ending clean mount"), "MOUNT-LOG-END"),
    (re.compile(r"Ending recovery"), "MOUNT-RECOVERY-END"),
    (re.compile(r"Unmounting Filesystem"), "UNMOUNT-BEGIN"),
    (re.compile(r"LOCK_RELEASE from node \d+ . no GRANTED entry"), "REL-NO-GRANTED-ENTRY"),
    (re.compile(r"lock request failed after \d+ retries"), "LOCKREQ-RETRIES-EXHAUSTED"),
    (re.compile(r"DLM inode lock failed"), "INODE-LOCK-FAILED"),
    (re.compile(r"DLM_TRACE: (\w+) (\w+)"), None),
    (re.compile(r"hung_task|blocked for more than"), "HUNG-TASK"),
    (re.compile(r"Corruption|corrupt", re.I), "CORRUPT-WORD"),
    (re.compile(r"xfs_force_shutdown|Shutting down filesystem", re.I), "FS-SHUTDOWN"),
]

DEFAULT_FIELDS = ("type,ino,ag,page,seq,owner,node,sender,master,target,to,from,"
                  "why,via,how,mode,hmode,holder,state,rc,rel_id,sends,slot,inc,"
                  "auth,cleared,cand,visited,held_ms,dur_ms,attempts,retx,"
                  "released,ack_rc,held_after,held,pr,ex,unacked,count")


def stamp(line, tz_hours):
    m = STAMP.match(line)
    if not m:
        return None, None
    t = datetime.datetime(int(m.group(6)), MONTHS[m.group(1)], int(m.group(2)),
                          int(m.group(3)), int(m.group(4)), int(m.group(5)))
    return t + datetime.timedelta(hours=tz_hours), line[m.end():]


def tag_of(body):
    m = TAG.search(body)
    if m:
        return m.group(1)
    for pat, name in SHAPES:
        s = pat.search(body)
        if s:
            return name if name else "DLM_TRACE:%s_%s" % (s.group(1), s.group(2))
    return None


def when(text, day):
    if text is None:
        return None
    if "T" in text:
        return datetime.datetime.strptime(text, "%Y-%m-%dT%H:%M:%S")
    h, m, s = (int(x) for x in text.split(":"))
    return datetime.datetime(day.year, day.month, day.day, h, m, s)


def nodes_of(run_dir, only):
    found = sorted(os.path.basename(p)[len("kernlog_"):-len(".gz")]
                   for p in glob.glob(os.path.join(run_dir, "kernlog_*.gz")))
    if only:
        want = only.split(",")
        found = [n for n in found if n in want]
    if not found:
        sys.exit("no kernlog_<node>.gz in %s" % run_dir)
    return found


def lines(run_dir, node, since, until, tz_hours):
    path = os.path.join(run_dir, "kernlog_%s.gz" % node)
    with gzip.open(path, "rt", errors="replace") as f:
        for raw in f:
            t, body = stamp(raw, tz_hours)
            if t is None or t < since or (until and t > until):
                continue
            yield t, body.rstrip("\n")


def fields_of(body, keep):
    out = []
    for k, v in FIELD.findall(body):
        if k in keep:
            out.append("%s=%s" % (k, v))
    return " ".join(out)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("run_dir")
    ap.add_argument("mode", choices=("counts", "timeline", "mounts", "imports"))
    ap.add_argument("--since")
    ap.add_argument("--until")
    ap.add_argument("--tz-hours", type=float, default=0)
    ap.add_argument("--nodes", help="comma-separated; default every node in the directory")
    ap.add_argument("--tags", help="comma-separated tags (prefix match) to keep")
    ap.add_argument("--match", help="regex on the line body; kept lines must match")
    ap.add_argument("--fields", default=DEFAULT_FIELDS)
    ap.add_argument("--min", type=int, default=1, help="counts: hide tags below this")
    ap.add_argument("--limit", type=int, default=120, help="timeline: lines printed")
    ap.add_argument("--collapse", type=int, default=3,
                    help="timeline: print at most this many of one node+tag+field-shape, "
                         "then count the rest (0 = print all)")
    ap.add_argument("--width", type=int, default=200)
    args = ap.parse_args()

    rid = RUNID.search(os.path.basename(os.path.normpath(args.run_dir)))
    if not rid and not (args.since and "T" in args.since):
        sys.exit("the directory name carries no run id; give --since YYYY-MM-DDTHH:MM:SS")
    day = (datetime.datetime.strptime(rid.group(1) + rid.group(2), "%Y%m%d%H%M%S")
           if rid else when(args.since, None))
    since = when(args.since, day) if args.since else day
    until = when(args.until, day)
    nodes = nodes_of(args.run_dir, args.nodes)
    tags = [t for t in (args.tags or "").split(",") if t]
    pat = re.compile(args.match) if args.match else None
    keep = set(args.fields.split(","))
    print("# %s window %s .. %s nodes=%s" % (
        args.run_dir, since.strftime("%Y-%m-%dT%H:%M:%S"),
        until.strftime("%H:%M:%S") if until else "end", ",".join(nodes)))

    def wanted(tag, body):
        if tags and not (tag and any(tag.startswith(t) for t in tags)):
            return False
        if pat and not pat.search(body):
            return False
        return True

    if args.mode == "counts":
        for n in nodes:
            c = collections.Counter()
            total = 0
            first = last = None
            for t, body in lines(args.run_dir, n, since, until, args.tz_hours):
                total += 1
                first = first or t
                last = t
                tag = tag_of(body)
                if tag and wanted(tag, body):
                    c[tag] += 1
            span = ("%s..%s" % (first.strftime("%H:%M:%S"), last.strftime("%H:%M:%S"))
                    if first else "-")
            print("%s: lines=%d span=%s" % (n, total, span))
            for tag, v in sorted(c.items(), key=lambda kv: (-kv[1], kv[0])):
                if v >= args.min:
                    print("   %7d  %s" % (v, tag))
        return

    if args.mode == "imports":
        init = re.compile(r"DLM init: node_id=(\d+)")
        imp = re.compile(r"P-TAUTH-IMPORT-ACTIVE .*\bowner=(\d+) .*\bmode=(\w+)")
        members = set()
        seen = {}
        for n in nodes:
            rows = []
            retired = collections.Counter()
            for t, body in lines(args.run_dir, n, since, until, args.tz_hours):
                m = init.search(body)
                if m:
                    members.add(m.group(1))
                    continue
                m = imp.search(body)
                if m:
                    rows.append((m.group(1), m.group(2)))
                    continue
                tag = tag_of(body)
                if tag and (tag.startswith("P-TAUTH-IMPORT-RETIRE") or
                            tag.startswith("P-TAUTH-IMPORT-RESIDUE") or
                            tag.startswith("P-TAUTH-SETTLED-")):
                    retired[tag] += 1
                    # how each retired holder's tenancy had ended
                    if tag == "P-TAUTH-SETTLED-RETIRE":
                        w = re.search(r"\bwhy=([a-z-]+)", body)
                        retired["why:" + (w.group(1) if w else "?")] += 1
            seen[n] = (rows, retired)
        print("# members mounted in the window: %d" % len(members))
        for n in nodes:
            rows, retired = seen[n]
            c = collections.Counter()
            departed = 0
            for owner, mode in rows:
                who = ("unknown" if owner == "4294967295" else
                       "member" if owner in members else "departed")
                departed += who == "departed"
                c["%s_%s" % (who, mode)] += 1
            print("IMPORTS %s total=%d departed=%d %s retired=%s" % (
                n, len(rows), departed,
                " ".join("%s=%d" % kv for kv in sorted(c.items())) or "-",
                ",".join("%s:%d" % kv for kv in sorted(retired.items())) or "-"))
        return

    if args.mode == "mounts":
        names = ("MOUNT-BEGIN", "MOUNT-LOG-END", "MOUNT-RECOVERY-END", "UNMOUNT-BEGIN",
                 "HUNG-TASK", "FS-SHUTDOWN", "INODE-LOCK-FAILED",
                 "LOCKREQ-RETRIES-EXHAUSTED")
        for n in nodes:
            ev = []
            for t, body in lines(args.run_dir, n, since, until, args.tz_hours):
                tag = tag_of(body)
                if tag in names:
                    ev.append("%s %s" % (t.strftime("%H:%M:%S"), tag))
            print("%s: %s" % (n, " | ".join(ev) if ev else "-"))
        return

    rows = []
    for n in nodes:
        for t, body in lines(args.run_dir, n, since, until, args.tz_hours):
            tag = tag_of(body)
            if not wanted(tag, body):
                continue
            if not tag and not pat:
                continue
            rows.append((t, n, tag or "-", fields_of(body, keep)))
    rows.sort(key=lambda r: r[0])
    seen = collections.Counter()
    printed = 0
    for t, n, tag, fl in rows:
        shape = (n, tag, re.sub(r"\d+", "N", fl))
        seen[shape] += 1
        if args.collapse and seen[shape] > args.collapse:
            continue
        if printed >= args.limit:
            continue
        printed += 1
        print(("%s %s %s | %s" % (t.strftime("%H:%M:%S"), n, tag, fl))[:args.width])
    print("# matched=%d printed=%d" % (len(rows), printed))
    over = [(v, s) for s, v in seen.items() if args.collapse and v > args.collapse]
    for v, (n, tag, shp) in sorted(over, key=lambda x: -x[0])[:40]:
        print(("# x%d %s %s | %s" % (v, n, tag, shp))[:args.width])


if __name__ == "__main__":
    main()

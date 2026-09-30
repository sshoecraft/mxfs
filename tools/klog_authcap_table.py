#!/usr/bin/env python3
"""Tabulate MXFS authority-capture counters from per-node kernel logs.

Input: one gzip text file per node, klog_test<N>.txt.gz, captured with
`journalctl -o short-unix`, one record per line:

    <epoch>.<usec> <host> kernel: mxfs: <payload>

Per node it extracts:
  A  P240-AUTHCAP         line count; the last line before T0+cut and the last
                          line in the file (named counters, other pairs, and
                          the pw_by_outcome tail)
  B  P239-OWNAUTH-NONDUR  substring line count, split into record lines (token
                          "P239-OWNAUTH-NONDUR" followed by a space) and other
                          lines (for example the "P239-OWNAUTH-NONDURABLE-blft:"
                          histogram); for record lines the counts grouped by
                          (outcome, blft, comm, mode, unpub), distinct ino per
                          outcome, and first and last timestamp
  C  P239-OWNAUTH         line count and the last histogram line
  D  line counts for a fixed list of substrings, plus the distinct tokens each
     substring matched (a substring can be a prefix of a longer tag)
  E  P228-TOKCLASS        line count and the last line
  F  P227-TOKENSUM        one row per line

Printed payloads have everything up to and including "mxfs: " removed (when a
line carries no "mxfs: ", everything before the tag is removed instead), are
capped at 400 characters, and are suppressed when they contain a stack-trace
marker.  A substring count is the number of lines containing the substring,
each line counted once.

usage:
  python3 tools/klog_authcap_table.py --dir EVIDENCE_DIR --t0 EPOCH \
      [--nodes 1,2,4,5,7,8] [--cut 10] [--rows 60] [--group-rows 40] \
      [--out FILE]

The report is printed with the B group table and the F table capped at
--group-rows and --rows (the pre-cap totals are stated).  --out writes the same
report uncapped.
"""

import argparse
import collections
import gzip
import re
import sys

COUNT_SUBSTRINGS = [
    "P107-PUBLISH",
    "P-UNPUB-OWNED-META",
    "P24-DIRSLOW",
    "P24-WORKER claimed",
    "P241-AUTHTRY",
    "P-AUTHCAP-VOID",
    "P128-REARM-UNPUB",
    "P128-PUBLISH-BAIL",
    "P109-PUBLISH-FAIL",
    "P-PUB-DRAIN-TIMEOUT",
    "P227-FR-ATOMIC-SKIP",
    "P227-TOKENSUM",
    "P-FR-BUF-LSN",
    "P163-RECOVERY-COMPLETE",
    "P241-RECOV-TERMINAL",
    "declaring dead",
    "P228-TOKCLASS",
]
AUDIT_SUBSTRINGS = COUNT_SUBSTRINGS + ["P240-AUTHCAP", "P239-OWNAUTH"]
AUDIT_RE = {sub: re.compile(r"\S*" + re.escape(sub) + r"\S*") for sub in AUDIT_SUBSTRINGS}

TAG_AUTHCAP = "P240-AUTHCAP"
TAG_NONDUR = "P239-OWNAUTH-NONDUR"
TAG_NONDUR_RECORD = "P239-OWNAUTH-NONDUR "
TAG_OWNAUTH = "P239-OWNAUTH "
TAG_TOKCLASS = "P228-TOKCLASS"
TAG_TOKENSUM = "P227-TOKENSUM"

AUTH_FIELDS = ["win", "relog", "mismatch", "noblft", "blftchg", "nocap",
               "retype_ok", "retype_mixed", "retype_unproven"]
SUM_FIELDS = ["buf_items", "tokened", "classless", "untagged", "wapply", "wskip"]
NONDUR_NEEDED = ("outcome", "blft", "mode", "unpub", "ino")

TS_RE = re.compile(r"^(\d{10}\.\d{6}) ")
PAIR_RE = re.compile(r"(\w+)=(\S+)")
NONDUR_TOKEN_RE = re.compile(r"\S*" + re.escape(TAG_NONDUR) + r"\S*")
TXN_KEY_RE = re.compile(r"txn|tid|trans|tx", re.I)
FORBIDDEN = ("Call Trace", "RIP:", " +0x")
PAYLOAD_CAP = 400


def payload_of(line, tag):
    i = line.find("mxfs: ")
    if i >= 0:
        return line[i + 6:].rstrip("\n")
    j = line.find(tag)
    return (line[j:] if j >= 0 else line).rstrip("\n")


def safe(text, cap=PAYLOAD_CAP):
    for bad in FORBIDDEN:
        if bad in text:
            return "[suppressed: text contains %r]" % bad
    if len(text) > cap:
        return text[:cap] + " [+%d chars cut]" % (len(text) - cap)
    return text


def num(text):
    try:
        return int(text, 10)
    except (TypeError, ValueError):
        return None


def numkey(text):
    if text.isdigit():
        return (0, int(text), "")
    return (1, 0, text)


def fmt_off(ts, t0):
    if ts is None:
        return "-"
    return "T0%+.3f" % (ts - t0)


def fmt_epoch(ts):
    if ts is None:
        return "-"
    return "%.6f" % ts


def md_table(header, rows):
    def cell(value):
        return str(value).replace("|", "\\|")
    out = ["| " + " | ".join(cell(h) for h in header) + " |",
           "|" + "|".join(["---"] * len(header)) + "|"]
    for row in rows:
        out.append("| " + " | ".join(cell(c) for c in row) + " |")
    return out


def widen(pair, ts):
    """Return (min, max) of a running pair and a new timestamp."""
    if ts is None:
        return pair
    if pair is None:
        return (ts, ts)
    return (min(pair[0], ts), max(pair[1], ts))


class NodeStats:
    def __init__(self, node, path):
        self.node = node
        self.name = "test%d" % node
        self.path = path
        self.lines = 0
        self.no_ts_lines = 0
        self.out_of_order = 0
        self.first_ts = None
        self.last_ts = None
        self.counts = collections.Counter()
        self.variants = collections.defaultdict(collections.Counter)
        self.auth_n = 0
        self.auth_before_cut_n = 0
        self.auth_first_ts = None
        self.auth_last_ts = None
        self.auth_pre = None
        self.auth_last = None
        self.nd_n = 0
        self.nd_range = None
        self.rec_n = 0
        self.rec_unparsed = 0
        self.rec_range = None
        self.oth_n = 0
        self.oth_range = None
        self.oth_last = None
        self.nd_groups = collections.Counter()
        self.nd_outcome_lines = collections.Counter()
        self.nd_ino = collections.defaultdict(set)
        self.nd_ino0 = collections.Counter()
        self.oa_n = 0
        self.oa_last = None
        self.tc_n = 0
        self.tc_last = None
        self.tsum_rows = []


def scan(node, path, cut_ts):
    st = NodeStats(node, path)
    prev = None
    with gzip.open(path, "rt", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            st.lines += 1
            m = TS_RE.match(line)
            ts = None
            if m:
                ts = float(m.group(1))
                if st.first_ts is None:
                    st.first_ts = ts
                st.last_ts = ts
                if prev is not None and ts < prev:
                    st.out_of_order += 1
                prev = ts
            else:
                st.no_ts_lines += 1

            for sub in AUDIT_SUBSTRINGS:
                if sub in line:
                    st.counts[sub] += 1
                    st.variants[sub][AUDIT_RE[sub].search(line).group(0)] += 1

            if TAG_AUTHCAP in line:
                st.auth_n += 1
                payload = payload_of(line, TAG_AUTHCAP)
                if ts is not None:
                    if st.auth_first_ts is None:
                        st.auth_first_ts = ts
                    st.auth_last_ts = ts
                    if ts < cut_ts:
                        st.auth_before_cut_n += 1
                        st.auth_pre = (ts, payload)
                st.auth_last = (ts, payload)

            if TAG_NONDUR in line:
                st.nd_n += 1
                st.nd_range = widen(st.nd_range, ts)
                if TAG_NONDUR_RECORD in line:
                    st.rec_n += 1
                    st.rec_range = widen(st.rec_range, ts)
                    payload = payload_of(line, TAG_NONDUR)
                    head, sep, comm = payload.partition(" comm=")
                    kv = dict(PAIR_RE.findall(head))
                    if not sep or any(k not in kv for k in NONDUR_NEEDED):
                        st.rec_unparsed += 1
                    else:
                        key = (kv["outcome"], kv["blft"], comm.strip(), kv["mode"], kv["unpub"])
                        st.nd_groups[key] += 1
                        st.nd_outcome_lines[kv["outcome"]] += 1
                        st.nd_ino[kv["outcome"]].add(kv["ino"])
                        if kv["ino"] == "0":
                            st.nd_ino0[kv["outcome"]] += 1
                else:
                    st.oth_n += 1
                    st.oth_range = widen(st.oth_range, ts)
                    st.oth_last = (ts, payload_of(line, TAG_NONDUR),
                                   NONDUR_TOKEN_RE.search(line).group(0))

            if TAG_OWNAUTH in line:
                st.oa_n += 1
                st.oa_last = (ts, payload_of(line, TAG_OWNAUTH))

            if TAG_TOKCLASS in line:
                st.tc_n += 1
                st.tc_last = (ts, payload_of(line, TAG_TOKCLASS))

            if TAG_TOKENSUM in line:
                payload = payload_of(line, TAG_TOKENSUM)
                head, sep, tail = payload.partition("classless_blft:")
                st.tsum_rows.append((ts, dict(PAIR_RE.findall(head)),
                                     tail.strip() if sep else None))
    return st


def render_input(stats, args):
    out = ["## Input", ""]
    out.append("command: python3 " + " ".join(sys.argv))
    out.append("T0 = %.0f epoch; cut = T0+%g s = %.0f epoch; timestamps are epoch.usec "
               "(journalctl -o short-unix, UTC); 'before cut' means ts < cut" %
               (args.t0, args.cut, args.t0 + args.cut))
    out.append("")
    out += md_table(
        ["node", "lines", "first t", "last t", "lines w/o epoch prefix", "out-of-order ts"],
        [[st.name, st.lines, fmt_off(st.first_ts, args.t0), fmt_off(st.last_ts, args.t0),
          st.no_ts_lines, st.out_of_order] for st in stats])
    return out


def render_a(stats, args):
    out = ["## A. P240-AUTHCAP", ""]
    out += md_table(
        ["node", "lines", "lines before cut", "first t", "last t"],
        [[st.name, st.auth_n, st.auth_before_cut_n, fmt_off(st.auth_first_ts, args.t0),
          fmt_off(st.auth_last_ts, args.t0)] for st in stats])
    out.append("")
    which_pre = "last<T0+%g" % args.cut
    rows = []
    tails = []
    for st in stats:
        for which, sel in ((which_pre, st.auth_pre), ("last-in-file", st.auth_last)):
            if sel is None:
                rows.append([st.name, which, "no such line"] + ["-"] * (len(AUTH_FIELDS) + 1))
                tails.append("- %s %s: no such line" % (st.name, which))
                continue
            ts, payload = sel
            head, sep, tail = payload.partition("pw_by_outcome:")
            pairs = PAIR_RE.findall(head)
            kv = dict(pairs)
            others = " ".join("%s=%s" % (k, v) for k, v in pairs if k not in AUTH_FIELDS)
            rows.append([st.name, which, fmt_off(ts, args.t0)] +
                        [kv.get(f, "-") for f in AUTH_FIELDS] + [others or "-"])
            tails.append("- %s %s pw_by_outcome: %s" %
                         (st.name, which,
                          safe(tail.strip()) if sep else "(no pw_by_outcome: on this line)"))
    out += md_table(["node", "which", "t"] + AUTH_FIELDS + ["other pairs"], rows)
    out.append("")
    out.append("pw_by_outcome tails (verbatim, prefix stripped):")
    out += tails
    return out


def render_b(stats, args, capped):
    out = ["## B. P239-OWNAUTH-NONDUR", ""]
    out.append("the substring matches two line types: record lines (token P239-OWNAUTH-NONDUR "
               "followed by a space) and other lines (token shown in the 'other lines' section)")
    out.append("")
    rows = [[st.name, st.nd_n, st.rec_n, st.rec_unparsed, st.oth_n] for st in stats]
    rows.append(["total", sum(st.nd_n for st in stats), sum(st.rec_n for st in stats),
                 sum(st.rec_unparsed for st in stats), sum(st.oth_n for st in stats)])
    out += md_table(["node", "substring lines", "record lines", "record lines unparsed",
                     "other lines"], rows)
    out.append("")
    rows = []
    for st in stats:
        for label, rng in (("substring (all)", st.nd_range), ("record lines", st.rec_range),
                           ("other lines", st.oth_range)):
            rows.append([st.name, label,
                         fmt_off(rng[0], args.t0) if rng else "-",
                         fmt_off(rng[1], args.t0) if rng else "-",
                         fmt_epoch(rng[0]) if rng else "-",
                         fmt_epoch(rng[1]) if rng else "-"])
    out += md_table(["node", "set", "min t", "max t", "min epoch", "max epoch"], rows)
    out.append("")
    out.append("record lines per outcome (distinct ino counts include ino=0 as a value; "
               "ino0 = lines with ino=0):")
    rows = []
    for st in stats:
        for oc in sorted(st.nd_outcome_lines, key=numkey):
            inos = sorted(st.nd_ino[oc], key=numkey)
            rows.append([st.name, oc, st.nd_outcome_lines[oc], len(inos), st.nd_ino0[oc],
                         ",".join(inos) if len(inos) <= 4 else "more than 4"])
    out += md_table(["node", "outcome", "lines", "distinct ino", "ino0 lines", "ino values"], rows)
    out.append("")

    total = collections.Counter()
    for st in stats:
        for key, n in st.nd_groups.items():
            total[key] += n
    keys = sorted(total, key=lambda k: (-total[k],) + tuple(numkey(x) for x in k))
    shown = keys[:args.group_rows] if capped else keys
    parsed_total = sum(total.values())
    out.append("record-line groups by (outcome, blft, comm, mode, unpub): %d distinct groups over "
               "%d parsed record lines (%d record lines unparsed); showing %d groups covering "
               "%d of %d lines, sorted by total descending" %
               (len(keys), parsed_total, sum(st.rec_unparsed for st in stats), len(shown),
                sum(total[k] for k in shown), parsed_total))
    rows = []
    for key in shown:
        rows.append(list(key) + [st.nd_groups.get(key, 0) for st in stats] + [total[key]])
    out += md_table(["outcome", "blft", "comm", "mode", "unpub"] + [st.name for st in stats] +
                    ["total"], rows)
    out.append("")
    out.append("other lines (substring matched, not a record line): last per node, verbatim, prefix stripped:")
    for st in stats:
        if st.oth_last:
            out.append("- %s: %d lines, token %s, last: %s" %
                       (st.name, st.oth_n, st.oth_last[2], safe(st.oth_last[1])))
        else:
            out.append("- %s: 0 lines" % st.name)
    return out


def render_last(title, count_attr, last_attr, stats, args):
    out = [title, ""]
    out += md_table(["node", "lines", "last t"],
                    [[st.name, getattr(st, count_attr),
                      fmt_off(getattr(st, last_attr)[0], args.t0) if getattr(st, last_attr) else "-"]
                     for st in stats])
    out.append("")
    out.append("last line per node (verbatim, prefix stripped):")
    for st in stats:
        last = getattr(st, last_attr)
        out.append("- %s: %s" % (st.name, safe(last[1]) if last else "no such line"))
    return out


def render_d(stats, args):
    out = ["## D. line counts per substring (each line counted once)", ""]
    rows = []
    for sub in COUNT_SUBSTRINGS:
        rows.append([sub] + [st.counts[sub] for st in stats] + [sum(st.counts[sub] for st in stats)])
    rows.append(["(lines in file)"] + [st.lines for st in stats] + [sum(st.lines for st in stats)])
    out += md_table(["substring"] + [st.name for st in stats] + ["total"], rows)
    return out


def render_variants(stats, capped):
    out = ["## D2. distinct whitespace-delimited tokens containing each substring", ""]
    quiet = 0
    for sub in AUDIT_SUBSTRINGS:
        merged = collections.Counter()
        for st in stats:
            merged.update(st.variants[sub])
        if len(merged) > 1:
            parts = []
            for tok, n in merged.most_common(8):
                split = " ".join("%s=%d" % (st.name, st.variants[sub][tok])
                                 for st in stats if st.variants[sub][tok])
                parts.append("%r x%d (%s)" % (tok, n, split))
            out.append("- %r: %d tokens: %s%s" % (sub, len(merged), "; ".join(parts),
                                                   " (+more)" if len(merged) > 8 else ""))
        elif capped:
            quiet += 1
        elif len(merged) == 1:
            tok, n = merged.most_common(1)[0]
            out.append("- %r: 1 token: %r x%d" % (sub, tok, n))
        else:
            out.append("- %r: no lines" % sub)
    if capped:
        out.append("- the other %d substrings matched one token or none (uncapped file lists each)" % quiet)
    return out


def render_f(stats, args, capped):
    out = ["## F. P227-TOKENSUM", ""]
    all_rows = [(st, ts, kv, tail) for st in stats for (ts, kv, tail) in st.tsum_rows]
    summary = []
    for st in stats:
        cols = [sum(num(kv.get(f)) or 0 for row_ts, kv, row_tail in st.tsum_rows) for f in SUM_FIELDS]
        classless_rows = sum(1 for row_ts, kv, row_tail in st.tsum_rows
                             if (num(kv.get("classless")) or 0) > 0)
        untagged_rows = sum(1 for row_ts, kv, row_tail in st.tsum_rows
                            if (num(kv.get("untagged")) or 0) > 0)
        summary.append([st.name, len(st.tsum_rows)] + cols + [classless_rows, untagged_rows])
    out += md_table(["node", "lines"] + ["sum " + f for f in SUM_FIELDS] +
                    ["rows classless>0", "rows untagged>0"], summary)
    out.append("")
    keys_seen = collections.Counter(k for row_st, row_ts, kv, row_tail in all_rows for k in kv)
    txn_keys = sorted(k for k in keys_seen if TXN_KEY_RE.search(k))
    out.append("keys seen across %d lines: %d distinct; txn/tid-like keys: %s" %
               (len(all_rows), len(keys_seen), ", ".join(txn_keys) if txn_keys else "none"))
    out.append("")
    shown = all_rows[:args.rows] if capped else all_rows
    out.append("rows: showing %d of %d total (node order, then log order)" % (len(shown), len(all_rows)))
    header = ["node", "t", "lsn"] + txn_keys + SUM_FIELDS + ["classless_blft tail"]
    rows = []
    for st, ts, kv, tail in shown:
        rows.append([st.name, fmt_off(ts, args.t0), kv.get("lsn", "-")] +
                    [kv.get(k, "-") for k in txn_keys] + [kv.get(f, "-") for f in SUM_FIELDS] +
                    [safe(tail) if tail is not None else "(no classless_blft: on this line)"])
    out += md_table(header, rows)
    return out


def render(stats, args, capped):
    out = ["# klog authcap tables", ""]
    out += render_input(stats, args)
    out.append("")
    out += render_a(stats, args)
    out.append("")
    out += render_b(stats, args, capped)
    out.append("")
    out += render_last("## C. P239-OWNAUTH (histogram line, trailing space in the pattern)",
                       "oa_n", "oa_last", stats, args)
    out.append("")
    out += render_d(stats, args)
    out.append("")
    out += render_variants(stats, capped)
    out.append("")
    out += render_last("## E. P228-TOKCLASS", "tc_n", "tc_last", stats, args)
    out.append("")
    out += render_f(stats, args, capped)
    return out


def main():
    ap = argparse.ArgumentParser(description="Tabulate MXFS authority-capture counters from klog_test<N>.txt.gz")
    ap.add_argument("--dir", required=True, help="directory holding klog_test<N>.txt.gz")
    ap.add_argument("--t0", type=float, required=True, help="run T0 as epoch seconds")
    ap.add_argument("--nodes", default="1,2,4,5,7,8", help="comma list of node numbers")
    ap.add_argument("--cut", type=float, default=10.0, help="seconds after T0 for the 'before' selection")
    ap.add_argument("--rows", type=int, default=60, help="F table row cap in the printed report")
    ap.add_argument("--group-rows", type=int, default=40, help="B group table row cap in the printed report")
    ap.add_argument("--out", help="also write the uncapped report to this file")
    args = ap.parse_args()

    stats = []
    for node in [int(x) for x in args.nodes.split(",") if x]:
        path = "%s/klog_test%d.txt.gz" % (args.dir.rstrip("/"), node)
        stats.append(scan(node, path, args.t0 + args.cut))

    if args.out:
        with open(args.out, "w") as fh:
            fh.write("\n".join(render(stats, args, False)) + "\n")
    print("\n".join(render(stats, args, True)))


if __name__ == "__main__":
    main()

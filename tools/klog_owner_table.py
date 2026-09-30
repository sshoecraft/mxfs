#!/usr/bin/env python3
"""Tabulate P239-OWNAUTH-OWNER records and recovery counters from per-node kernel logs.

Input: one gzip text file per node, klog_test<N>.txt.gz, captured with
`journalctl -k -f -o short-unix`, one record per line:

    <epoch>.<usec> <host> kernel: <message>

Sections (the numbers are the lap request's step labels):

  4a  per node: line count, first and last timestamp as T0+seconds
  4b  P239-OWNAUTH-OWNER: line count per node, and one table over all nodes
      grouped by (outcome, blft, mode, unpub, reused, selfc, try, try_mode, tg,
      try_line, line, clr, comm) with a count per node and a total, sorted by
      total descending.  tg compares try_gen with gen as integers: "eq",
      "lt" (try_gen < gen), "gt" (try_gen > gen), or "??" when either value
      does not parse as an integer (never folded into another value).
  4c  the same grouping over the victims' lines that fall inside the last
      --tail seconds of each victim's own log; "last" is the largest
      timestamp in that victim's file
  4d  per node: the last line containing "P239-OWNAUTH " (trailing space) and
      the last line containing "P240-AUTHCAP"
  4e  lines per node containing each of a fixed list of substrings, each line
      counted once per substring; the distinct tokens a substring matched
      are listed when there is more than one (a substring can be a prefix of
      a longer tag)
  4f  the payloads of the lines carrying the replayer's own account of a
      victim slice.  A shape is the payload with each digit run replaced by
      N; at most --per-shape lines of one shape are shown (earliest first), so
      one message repeated on every survivor does not crowd out the lines
      that occur once; the shown lines are then capped at --fr-cap, spread
      evenly over the categories that have lines.  Every omitted line is
      accounted for by shape, count, nodes and first and last time, and the
      pre-cap totals are stated.  The full report also lists every stored line.
  4g  P227-TOKENSUM: lines per node, the sums of its counters, the lines with
      classless>0, and the lines containing "REDUNDANT"

A printed payload has everything before the message removed: a line carrying
"MXFS foreign replay" keeps everything from that text on; any other line loses
everything up to and including "mxfs: "; a line with neither loses the journal
prefix "<epoch> <host> kernel: "; a line in no journal format starts at the
tag that selected it.  Payloads are capped (600 characters in 4d, 900 in 4f)
and are replaced by a marker when the line contains a stack-trace marker
("Call Trace", "RIP:" or " +0x").

A substring count is the number of lines containing the substring, each line
counted once, over every line of the file.

usage:
  python3 tools/klog_owner_table.py --dir EVIDENCE_DIR --summary SUMMARY_TXT \
      [--nodes 1,2,3,4,5,6,7,8] [--victims 3,6] [--tail 3] \
      [--group-rows 40] [--fr-cap 30] [--per-shape 2] [--out FILE]

T0 comes from the first "T0=<epoch>" in --summary, or from --t0 EPOCH.  The
compact report goes to stdout; --out writes the full report, with no row cap
on 4b and 4c and with every 4f line (at most 2000 per node).  Exit status: 0
when every node file was read to its end, 3 when a node file was missing or
unreadable (the report is still printed, the node is named in it).
"""

import argparse
import collections
import concurrent.futures
import gzip
import re
import sys
import time
import zlib

TS_RE = re.compile(rb"^(\d{10}\.\d{6}) ")
PAIR_RE = re.compile(r"(\w+)=(\S+)")
T0_RE = re.compile(r"\bT0=(\d+(?:\.\d+)?)")
FORBIDDEN = ("Call Trace", "RIP:", " +0x")

OWNER_TAG = "P239-OWNAUTH-OWNER"
OWNAUTH_TAG = "P239-OWNAUTH "
AUTHCAP_TAG = "P240-AUTHCAP"
TOKENSUM_TAG = "P227-TOKENSUM"
REDUNDANT_TAG = "REDUNDANT"

OWNER_FIELDS = ("outcome", "blft", "mode", "unpub", "reused", "selfc", "gen",
                "try", "try_mode", "try_gen", "try_line", "line", "clr")
GROUP_COLUMNS = ("outcome", "blft", "mode", "unpub", "reused", "selfc", "try",
                 "try_mode", "tg", "try_line", "line", "clr", "comm")
SUM_FIELDS = ("buf_items", "tokened", "classless", "untagged", "wapply", "wskip")

COUNT_SUBSTRINGS = (
    "declaring dead", "P163-RECOVERY-COMPLETE", "P241-RECOV-TERMINAL",
    "P240-QUAR-IMPORT", "P240-RBLK-EIO-ABORT", "P240-QUAR-NSOP-REFUSE",
    "P227-FR-ATOMIC-SKIP", "P227-FR-REDUNDANT-SKIP", "P223-FR-UNTAGGED-SKIP",
    "P227-TOKENSUM", "P-FR-BUF-LSN", "P-FR-CANCEL-PASS1",
    "P-FR-IMAGE-CANCELLED-SKIP", "P273-SHADOW-EVAL", "P-RMAN-LOADED",
    "P56-NL-LOGGED-DIR-SKIP", "P218-RECOV-OWNED", "P218-WRITE-REFUSED",
    "P-RELMARK-REINSTALL-REFUSED", "P24-WORKER claimed", "P128-REARM-UNPUB",
    "P78-PUB-SKIP", "foreign replay of slot",
)
HIT_TAGS = ("foreign replay of slot", "slice replay", "P241-RECOV-TERMINAL ",
            "P-FR-CANCEL-PASS1", "P273-SHADOW-EVAL")

ALL_SUBSTRINGS = []
for sub in COUNT_SUBSTRINGS + (OWNER_TAG, OWNAUTH_TAG, AUTHCAP_TAG, REDUNDANT_TAG) + HIT_TAGS:
    if sub not in ALL_SUBSTRINGS:
        ALL_SUBSTRINGS.append(sub)
ALL_BYTES = [(sub, sub.encode()) for sub in ALL_SUBSTRINGS]
TOKEN_RES = {sub: re.compile(rb"\S*" + re.escape(sub.encode()) + rb"\S*")
             for sub in COUNT_SUBSTRINGS + (REDUNDANT_TAG,)}

PAYLOAD_CAP_LAST = 600
PAYLOAD_CAP_HIT = 900
HITS_STORED_PER_NODE = 2000
DIGITS_RE = re.compile(r"\d+")


def payload_of(text, tag):
    """The message with the journal prefix removed (rules in the module docstring)."""
    i = text.find("MXFS foreign replay")
    if i >= 0:
        return text[i:]
    i = text.find("mxfs: ")
    if i >= 0:
        return text[i + 6:]
    i = text.find("kernel: ")
    if i >= 0:
        return text[i + 8:]
    j = text.find(tag)
    return text[j:] if j >= 0 else text


def printable(text, tag, cap):
    for bad in FORBIDDEN:
        if bad in text:
            return "[suppressed: the line carries a stack-trace marker]"
    payload = payload_of(text, tag).rstrip()
    if len(payload) > cap:
        return payload[:cap] + " [+%d chars cut]" % (len(payload) - cap)
    return payload


def num(text):
    try:
        return int(text, 10)
    except (TypeError, ValueError):
        return None


def compare_gen(gen, try_gen):
    a = num(gen)
    b = num(try_gen)
    if a is None or b is None:
        return "??"
    if b == a:
        return "eq"
    return "lt" if b < a else "gt"


def fmt_off(ts, t0):
    if ts is None:
        return "-"
    return "T0%+.3f" % (ts - t0)


def withhold(lines):
    """Replace every rendered line that carries a stack-trace marker; return the lines and the count."""
    kept = []
    held = 0
    for line in lines:
        if any(bad in line for bad in FORBIDDEN):
            kept.append("[line withheld: it carries a stack-trace marker]")
            held += 1
        else:
            kept.append(line)
    return kept, held


def md_table(header, rows):
    def cell(value):
        return str(value).replace("|", "\\|")
    out = ["| " + " | ".join(cell(h) for h in header) + " |",
           "|" + "|".join(["---"] * len(header)) + "|"]
    for row in rows:
        out.append("| " + " | ".join(cell(c) for c in row) + " |")
    return out


class NodeStats:
    def __init__(self, node, path):
        self.node = node
        self.name = "test%d" % node
        self.path = path
        self.error = None
        self.lines = 0
        self.no_ts = 0
        self.out_of_order = 0
        self.first_ts = None
        self.last_ts = None
        self.counts = collections.Counter()
        self.tokens = collections.defaultdict(collections.Counter)
        self.owner_groups = collections.Counter()
        self.owner_rows = []
        self.owner_missing = collections.Counter()
        self.owner_tg_unknown = 0
        self.ownauth_last = None
        self.authcap_last = None
        self.tokensum_lines = 0
        self.tokensum_sums = collections.Counter()
        self.tokensum_classless_lines = 0
        self.tokensum_missing = collections.Counter()
        self.redundant_lines = 0
        self.fr_hits = []
        self.fr_dropped = 0


def absorb(st, raw, ts, hits, keep_rows):
    text = raw.decode("utf-8", "replace").rstrip("\n")
    for sub in hits:
        st.counts[sub] += 1
        rx = TOKEN_RES.get(sub)
        if rx is not None:
            st.tokens[sub][rx.search(raw).group(0).decode("utf-8", "replace")[:80]] += 1

    if OWNER_TAG in hits:
        i = text.find(OWNER_TAG)
        head, sep, comm = text[i + len(OWNER_TAG):].partition(" comm=")
        kv = dict(PAIR_RE.findall(head))
        for field in OWNER_FIELDS:
            if field not in kv:
                st.owner_missing[field] += 1
        if not sep:
            st.owner_missing["comm"] += 1
        tg = compare_gen(kv.get("gen"), kv.get("try_gen"))
        if tg == "??":
            st.owner_tg_unknown += 1
        key = (kv.get("outcome", "-"), kv.get("blft", "-"), kv.get("mode", "-"),
               kv.get("unpub", "-"), kv.get("reused", "-"), kv.get("selfc", "-"),
               kv.get("try", "-"), kv.get("try_mode", "-"), tg,
               kv.get("try_line", "-"), kv.get("line", "-"), kv.get("clr", "-"),
               comm.strip() if sep else "-")
        st.owner_groups[key] += 1
        if keep_rows:
            st.owner_rows.append((ts, key))

    if OWNAUTH_TAG in hits:
        st.ownauth_last = (ts, text)
    if AUTHCAP_TAG in hits:
        st.authcap_last = (ts, text)

    if TOKENSUM_TAG in hits:
        st.tokensum_lines += 1
        i = text.find(TOKENSUM_TAG)
        head = text[i + len(TOKENSUM_TAG):].partition("classless_blft:")[0]
        kv = dict(PAIR_RE.findall(head))
        for field in SUM_FIELDS + ("redundant",):
            value = num(kv.get(field))
            if value is None:
                st.tokensum_missing[field] += 1
            else:
                st.tokensum_sums[field] += value
        if (num(kv.get("classless")) or 0) > 0:
            st.tokensum_classless_lines += 1

    if REDUNDANT_TAG in hits:
        st.redundant_lines += 1

    cats = tuple(tag for tag in HIT_TAGS if tag in hits)
    if cats:
        if len(st.fr_hits) < HITS_STORED_PER_NODE:
            st.fr_hits.append((ts, cats, printable(text, cats[0], PAYLOAD_CAP_HIT)))
        else:
            st.fr_dropped += 1


def scan(node, path, keep_rows):
    st = NodeStats(node, path)
    prev = None
    try:
        with gzip.open(path, "rb") as fh:
            for raw in fh:
                st.lines += 1
                m = TS_RE.match(raw)
                ts = None
                if m is None:
                    st.no_ts += 1
                else:
                    ts = float(m.group(1))
                    if st.first_ts is None:
                        st.first_ts = ts
                    if st.last_ts is None or ts > st.last_ts:
                        st.last_ts = ts
                    if prev is not None and ts < prev:
                        st.out_of_order += 1
                    prev = ts
                hits = [sub for sub, sb in ALL_BYTES if sb in raw]
                if hits:
                    absorb(st, raw, ts, hits, keep_rows)
    except (OSError, EOFError, zlib.error) as exc:
        st.error = "%s: %s" % (type(exc).__name__, exc)
    return st


def find_t0(path):
    values = []
    first = None
    with open(path, "r", errors="replace") as fh:
        for line in fh:
            found = T0_RE.findall(line)
            if found:
                if first is None:
                    first = line.rstrip("\n")[:300]
                values.extend(found)
    return list(dict.fromkeys(values)), first


def group_table(stats, per_node, cap):
    total = collections.Counter()
    for counter in per_node:
        total.update(counter)
    keys = sorted(total, key=lambda k: (-total[k], k))
    shown = keys if cap is None else keys[:cap]
    rows = [list(k) + [c.get(k, 0) for c in per_node] + [total[k]] for k in shown]
    header = list(GROUP_COLUMNS) + [st.name for st in stats] + ["total"]
    return md_table(header, rows), len(keys), sum(total.values()), len(shown)


def render_input(stats, args):
    out = ["## Input", ""]
    out.append("command: python3 " + " ".join(sys.argv))
    out.append("T0 = %s epoch (%s); timestamps are epoch.usec from journalctl -o short-unix, "
               "printed as T0+seconds" % (("%.0f" % args.t0_value), args.t0_note))
    bad = [st for st in stats if st.error]
    out.append("node files with a read error: %s" %
               ("; ".join("%s %s" % (st.name, st.error) for st in bad) if bad else "none"))
    return out


def render_4a(stats, t0):
    out = ["## 4a. per node: lines, first and last timestamp", ""]
    rows = [[st.name, st.lines, fmt_off(st.first_ts, t0), fmt_off(st.last_ts, t0),
             st.no_ts, st.out_of_order, st.error or "-"] for st in stats]
    out += md_table(["node", "lines", "first", "last", "lines w/o epoch prefix",
                     "out-of-order ts", "read error"], rows)
    return out


def render_4b(stats, args, capped):
    out = ["## 4b. P239-OWNAUTH-OWNER", ""]
    rows = []
    for st in stats:
        rows.append([st.name, st.counts[OWNER_TAG], sum(st.owner_groups.values()),
                     st.owner_tg_unknown,
                     " ".join("%s:%d" % (f, n) for f, n in sorted(st.owner_missing.items())) or "-"])
    rows.append(["total", sum(st.counts[OWNER_TAG] for st in stats),
                 sum(sum(st.owner_groups.values()) for st in stats),
                 sum(st.owner_tg_unknown for st in stats), ""])
    out += md_table(["node", "lines containing the tag", "lines grouped", "tg=?? lines",
                     "lines missing a field (field:lines)"], rows)
    out.append("")
    cap = args.group_rows if capped else None
    table, groups, lines, shown = group_table(stats, [st.owner_groups for st in stats], cap)
    out.append("groups by (%s): %d distinct groups over %d lines; showing %d, sorted by total "
               "descending" % (", ".join(GROUP_COLUMNS), groups, lines, shown))
    out += table
    return out


def render_4c(stats, args, capped):
    out = ["## 4c. victims only, lines within the last %g s of that victim's own log" % args.tail, ""]
    victims = [st for st in stats if st.node in args.victim_set]
    if not victims:
        out.append("no victim among the nodes read")
        return out
    counters = []
    for st in victims:
        if st.last_ts is None:
            counters.append(collections.Counter())
            out.append("- %s: no timestamped line in the log" % st.name)
            continue
        start = st.last_ts - args.tail
        window = collections.Counter(key for ts, key in st.owner_rows
                                     if ts is not None and ts >= start)
        counters.append(window)
        out.append("- %s: log ends %s; window T0%+.3f .. T0%+.3f; %d OWNER lines in the window "
                   "(of %d in the log)" % (st.name, fmt_off(st.last_ts, args.t0_value),
                                            start - args.t0_value, st.last_ts - args.t0_value,
                                            sum(window.values()), len(st.owner_rows)))
    out.append("")
    total = collections.Counter()
    for counter in counters:
        total.update(counter)
    keys = sorted(total, key=lambda k: (-total[k], k))
    cap = args.group_rows if capped else None
    shown = keys if cap is None else keys[:cap]
    out.append("groups: %d distinct over %d lines; showing %d, sorted by total descending" %
               (len(keys), sum(total.values()), len(shown)))
    rows = [list(k) + [c.get(k, 0) for c in counters] + [total[k]] for k in shown]
    out += md_table(list(GROUP_COLUMNS) + [st.name for st in victims] + ["total"], rows)
    return out


def render_4d(stats, args):
    out = ["## 4d. last P239-OWNAUTH (trailing space) and last P240-AUTHCAP line per node "
           "(payload, %d chars)" % PAYLOAD_CAP_LAST, ""]
    for st in stats:
        for label, tag, last in (("P239-OWNAUTH ", OWNAUTH_TAG, st.ownauth_last),
                                 ("P240-AUTHCAP", AUTHCAP_TAG, st.authcap_last)):
            if last is None:
                out.append("- %s %s: no such line (0 lines)" % (st.name, label))
            else:
                ts, text = last
                out.append("- %s %s %s (last of %d lines): %s" %
                           (st.name, label, fmt_off(ts, args.t0_value), st.counts[tag],
                            printable(text, tag, PAYLOAD_CAP_LAST)))
    return out


def render_4e(stats, args, capped):
    out = ["## 4e. lines per node containing each substring", ""]
    rows = []
    zero = []
    for sub in COUNT_SUBSTRINGS:
        counts = [st.counts[sub] for st in stats]
        row = [sub] + counts + [sum(counts)]
        if capped and sum(counts) == 0:
            zero.append(sub)
        else:
            rows.append(row)
    out += md_table(["substring"] + [st.name for st in stats] + ["total"], rows)
    zero_all = [sub for sub in COUNT_SUBSTRINGS if sum(st.counts[sub] for st in stats) == 0]
    out.append("")
    if capped and zero:
        out.append("all-zero rows omitted from the table above (%d): %s" %
                   (len(zero), "; ".join(zero)))
    out.append("all-zero rows in total: %d of %d" % (len(zero_all), len(COUNT_SUBSTRINGS)))
    if zero_all:
        out.append("the zeros were produced by: python3 %s  (per klog_test<N>.txt.gz, for every line of "
                   "the file, a bytes substring test of the exact text; a line counts once per "
                   "substring; no line pre-filter)" % " ".join(sys.argv))
    out.append("")
    multi = []
    for sub in COUNT_SUBSTRINGS + (REDUNDANT_TAG,):
        merged = collections.Counter()
        for st in stats:
            merged.update(st.tokens[sub])
        if len(merged) > 1:
            parts = []
            for tok, n in merged.most_common(6):
                split = ",".join("%s=%d" % (st.name, st.tokens[sub][tok])
                                 for st in stats if st.tokens[sub][tok])
                parts.append("%s x%d (%s)" % (tok, n, split))
            multi.append("- %r matched %d distinct tokens: %s%s" %
                         (sub, len(merged), "; ".join(parts),
                          " (+%d more)" % (len(merged) - 6) if len(merged) > 6 else ""))
    out.append("substrings that matched more than one distinct token: %d" % len(multi))
    out += multi
    return out


def chronological(hit):
    return (hit[0] is None, hit[0] or 0.0, hit[1])


def fair_take(buckets, cap):
    take = {name: 0 for name in buckets}
    active = [name for name in buckets if buckets[name]]
    remaining = cap
    while remaining > 0 and active:
        share = max(1, remaining // len(active))
        for name in list(active):
            n = min(share, len(buckets[name]) - take[name], remaining)
            take[name] += n
            remaining -= n
            if take[name] >= len(buckets[name]):
                active.remove(name)
            if remaining == 0:
                break
    return take


def render_4f(stats, args, capped):
    hits = []
    for st in stats:
        for ts, cats, payload in st.fr_hits:
            hits.append((ts, st.name, cats, payload))
    hits.sort(key=chronological)
    dropped = sum(st.fr_dropped for st in stats)
    total = len(hits) + dropped
    out = ["## 4f. payloads of the replayer's own account lines (%d chars each)" % PAYLOAD_CAP_HIT, ""]
    rows = []
    for tag in HIT_TAGS:
        counts = [st.counts[tag] for st in stats]
        rows.append([tag] + counts + [sum(counts)])
    out += md_table(["lines containing"] + [st.name for st in stats] + ["total"], rows)
    out.append("")
    out.append("distinct lines matching any of the five: %d (%d stored for printing, %d not stored "
               "because a node passed %d)" % (total, len(hits), dropped, HITS_STORED_PER_NODE))

    shape_total = collections.Counter(DIGITS_RE.sub("N", h[3]) for h in hits)
    seen = collections.Counter()
    kept = []
    repeats = []
    for h in hits:
        shape = DIGITS_RE.sub("N", h[3])
        if seen[shape] < args.per_shape:
            seen[shape] += 1
            kept.append(h)
        else:
            repeats.append(h)
    buckets = {tag: [h for h in kept if h[2][0] == tag] for tag in HIT_TAGS}
    take = fair_take(buckets, args.fr_cap)
    chosen = []
    cut = []
    for tag in HIT_TAGS:
        chosen += buckets[tag][:take[tag]]
        cut += buckets[tag][take[tag]:]
    chosen.sort(key=chronological)
    omitted = sorted(repeats + cut, key=chronological)
    out.append("shown %d of %d: at most %d lines of one shape are shown, earliest first (shape = the "
               "payload with each digit run replaced by N); omitted as further lines of a shown shape: "
               "%d; omitted by the %d-line cap: %d" %
               (len(chosen), total, args.per_shape, len(repeats), args.fr_cap, len(cut)))
    out.append("")
    for ts, name, cats, payload in chosen:
        mult = shape_total[DIGITS_RE.sub("N", payload)]
        out.append("- %s %s [%s]%s %s" % (name, fmt_off(ts, args.t0_value), "+".join(cats),
                                          " {shape x%d}" % mult if mult > 1 else "", payload))
    out.append("")
    by_shape = collections.OrderedDict()
    for h in omitted:
        by_shape.setdefault(DIGITS_RE.sub("N", h[3]), []).append(h)
    out.append("omitted lines, grouped by shape (%d lines in %d shapes):" % (len(omitted), len(by_shape)))
    for shape, lst in by_shape.items():
        out.append("- %d omitted of %d, nodes %s, %s .. %s: %s" %
                   (len(lst), shape_total[shape], ",".join(sorted({h[1] for h in lst})),
                    fmt_off(lst[0][0], args.t0_value), fmt_off(lst[-1][0], args.t0_value),
                    shape[:220] + (" [+%d chars cut]" % (len(shape) - 220) if len(shape) > 220 else "")))
    if not capped:
        out.append("")
        out.append("every stored line, chronological (%d):" % len(hits))
        for ts, name, cats, payload in hits:
            out.append("- %s %s [%s] %s" % (name, fmt_off(ts, args.t0_value), "+".join(cats), payload))
    return out


def render_4g(stats, args):
    out = ["## 4g. P227-TOKENSUM sums, and lines containing REDUNDANT", ""]
    rows = []
    for st in stats:
        rows.append([st.name, st.tokensum_lines] + [st.tokensum_sums[f] for f in SUM_FIELDS] +
                    [st.tokensum_classless_lines, st.tokensum_sums["redundant"],
                     st.redundant_lines])
    rows.append(["total", sum(st.tokensum_lines for st in stats)] +
                [sum(st.tokensum_sums[f] for st in stats) for f in SUM_FIELDS] +
                [sum(st.tokensum_classless_lines for st in stats),
                 sum(st.tokensum_sums["redundant"] for st in stats),
                 sum(st.redundant_lines for st in stats)])
    out += md_table(["node", "TOKENSUM lines"] + ["sum " + f for f in SUM_FIELDS] +
                    ["lines classless>0", "sum redundant= (extra)", "lines containing REDUNDANT"], rows)
    missing = ["%s %s:%d" % (st.name, f, n) for st in stats
               for f, n in sorted(st.tokensum_missing.items())]
    out.append("")
    out.append("TOKENSUM lines missing a counter (node field:lines): %s" %
               ("; ".join(missing) if missing else "none"))
    return out


def render(stats, args, started, capped):
    out = ["# klog owner tables", ""]
    out += render_input(stats, args)
    for section in (render_4a(stats, args.t0_value),
                    render_4b(stats, args, capped),
                    render_4c(stats, args, capped),
                    render_4d(stats, args),
                    render_4e(stats, args, capped),
                    render_4f(stats, args, capped),
                    render_4g(stats, args)):
        out.append("")
        out += section
    out.append("")
    out.append("script wall %.1f s" % (time.monotonic() - started))
    return out


def main():
    started = time.monotonic()
    ap = argparse.ArgumentParser(description="Tabulate P239-OWNAUTH-OWNER records and recovery "
                                             "counters from klog_test<N>.txt.gz")
    ap.add_argument("--dir", required=True, help="directory holding klog_test<N>.txt.gz")
    ap.add_argument("--summary", help="summary.txt whose first T0=<epoch> is the run's T0")
    ap.add_argument("--t0", type=float, help="run T0 as epoch seconds (instead of --summary)")
    ap.add_argument("--nodes", default="1,2,3,4,5,6,7,8", help="comma list of node numbers")
    ap.add_argument("--victims", default="3,6", help="comma list of victim node numbers")
    ap.add_argument("--tail", type=float, default=3.0, help="seconds at the end of a victim's log for 4c")
    ap.add_argument("--group-rows", type=int, default=40, help="4b and 4c group row cap in stdout")
    ap.add_argument("--fr-cap", type=int, default=30, help="4f line cap")
    ap.add_argument("--per-shape", type=int, default=2, help="4f: most lines shown of one message shape")
    ap.add_argument("--out", help="also write the full report to this file")
    args = ap.parse_args()

    if (args.summary is None) == (args.t0 is None):
        ap.error("give exactly one of --summary and --t0")
    if args.summary is not None:
        values, first = find_t0(args.summary)
        if not values:
            print("no T0=<epoch> in %s" % args.summary, file=sys.stderr)
            return 2
        args.t0_value = float(values[0])
        args.t0_note = "first of %s in %s: %s" % (values, args.summary, first)
    else:
        args.t0_value = args.t0
        args.t0_note = "--t0"
    args.victim_set = {int(x) for x in args.victims.split(",") if x}

    nodes = [int(x) for x in args.nodes.split(",") if x]
    with concurrent.futures.ProcessPoolExecutor(max_workers=len(nodes)) as pool:
        futures = [pool.submit(scan, n, "%s/klog_test%d.txt.gz" % (args.dir.rstrip("/"), n),
                               n in args.victim_set) for n in nodes]
        stats = [f.result() for f in futures]

    full, held = withhold(render(stats, args, started, False))
    if args.out:
        with open(args.out, "w") as fh:
            fh.write("\n".join(full) + "\nlines withheld for a stack-trace marker: %d\n" % held)
    compact, held = withhold(render(stats, args, started, True))
    print("\n".join(compact))
    print("lines withheld for a stack-trace marker: %d" % held)
    return 3 if any(st.error for st in stats) else 0


if __name__ == "__main__":
    sys.exit(main())

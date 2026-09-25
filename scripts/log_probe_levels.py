#!/usr/bin/env python3
"""
Move MXFS's diagnostic probes off the default kernel log.

A probe is a print whose text starts with an instrumentation tag ("P12-...",
"P-AGIFC-MOD", "PW-...").  They exist for the test harness, which reads them
back out of dmesg, and on a node doing ordinary work they are nearly the whole
kernel log: one 2-node suite run printed 76,541 lines on one node, 98% of them
probes.  This rewrites probe prints to the dynamic-debug variants
(mxfs_probe*, or MXFS_LOG_DEBUG through mxfs_pal_log), which print nothing
unless enabled:

    insmod mxfs.ko dyndbg=+p                              everything
    echo 'module mxfs +p' > /proc/dynamic_debug/control   at run time
    echo 'module mxfs format "P-AGIFC" +p' > ...           one family

WHICH PROBES STAY.  A probe keeps its level when it reports something an
operator must see -- its tag or text names a loss, corruption, shutdown,
withdrawal, fence, death, refusal, invariant breach, wedge, recovery and the
like -- and it is rare: it fired at most --rare-max times in the measured log
(--counts).  An ERR-level probe keeps its level unless it fired more often
than that, which makes it a routine diagnostic mislabelled as an error.

Usage:
    scripts/log_probe_levels.py --counts COUNTS.tsv [--rare-max 20] --report
    scripts/log_probe_levels.py --counts COUNTS.tsv [--rare-max 20] --apply

COUNTS.tsv: "<count>\\t<tag>" lines, the tags as they appear after any
"mxfs: " / "tauth: " prefixes, measured from a node's kernel log.
"""
import argparse
import glob
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SOURCES = ["xfs/**/*.c", "pal/linux/*.c", "dlm/*.c", "mxfs_clayer/*.c", "mxfs.c"]

SERIOUS = re.compile(
    r"LOST|LOSS|CORRUPT|SHUTDOWN|SHUT-DOWN|WITHDRAW|FAIL-?STOP|FAIL(ED)?[- ]CLOSED|"
    r"INVARIANT|UNPROVEN|WEDGE|STUCK|LEAK|\bBUG\b|DEATH|DEAD\b|FENCE|REFUS|ABORT|"
    r"INSANE|OVERFLOW|STALL|CONFLICT|POISON|QUARANTINE|RECOVER|REPLAY|JOIN|DEPART|"
    r"GOODBYE|TAKEOVER|EXPIRE|EVICTED-LIVE|VIOLAT|CLOBBER|DANGL|ORPHAN", re.I)

# "P12-DLMTR", "P-AGIFC-MOD", "PW-ADOPT", "P28E", and untagged all-caps
# hyphenated names ("EVICT-RING-FLAG", "CAW-ILOCK") -- all instrumentation
PROBE_TAG = re.compile(r"^(?:(?:mxfs|tauth|disklock|scsipr|lease|dlm|v5)\s*:\s*)*"
                       r"(P[0-9A-Z]*-[A-Za-z0-9_-]*|PW-[A-Za-z0-9_-]+|P[0-9]+[A-Z]*(?=[ =])|"
                       r"[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+(?=[ =:]))")

CALL = re.compile(r"\b(pr_warn_ratelimited|pr_warn_once|pr_warn|pr_info_ratelimited|"
                  r"pr_info_once|pr_info|pr_notice|pr_err_ratelimited|pr_err)\s*\(")
PAL = re.compile(r"\bmxfs_pal_log\s*\(\s*MXFS_LOG_(WARN|INFO|ERR)\s*,")
STR = re.compile(r'"((?:\\.|[^"\\])*)"')

REPLACE = {
    "pr_warn": "mxfs_probe", "pr_info": "mxfs_probe", "pr_notice": "mxfs_probe",
    "pr_err": "mxfs_probe",
    "pr_warn_ratelimited": "mxfs_probe_ratelimited",
    "pr_info_ratelimited": "mxfs_probe_ratelimited",
    "pr_err_ratelimited": "mxfs_probe_ratelimited",
    "pr_warn_once": "mxfs_probe_once", "pr_info_once": "mxfs_probe_once",
}


def first_literal(s, start):
    """The leading string literal(s) of a call's format argument, joined."""
    i = start
    out = []
    while True:
        while True:
            while i < len(s) and s[i] in " \t\n\\":
                i += 1
            if s.startswith("/*", i):          # a comment before the format
                i = s.find("*/", i) + 2
            elif s.startswith("//", i):
                i = s.find("\n", i)
            else:
                break
        m = STR.match(s, i)
        if not m:
            break
        out.append(m.group(1))
        i = m.end()
    return "".join(out)


def decide(level, text, counts, rare_max):
    """None = not a probe; 'keep' or 'debug'."""
    m = PROBE_TAG.match(text)
    if not m:
        return None, None
    tag = m.group(1).rstrip("-")
    n = counts.get(tag, 0)
    serious = bool(SERIOUS.search(text))
    if level == "ERR":
        return ("debug" if n > rare_max else "keep"), tag
    if serious and n <= rare_max:
        return "keep", tag
    return "debug", tag


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--counts", required=True)
    ap.add_argument("--rare-max", type=int, default=20)
    ap.add_argument("--report", action="store_true")
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--kept", help="write the kept probes here")
    a = ap.parse_args()
    counts = {}
    for line in open(a.counts):
        if "\t" in line:
            n, t = line.rstrip("\n").split("\t", 1)
            counts[t.rstrip("-")] = int(n)

    stats = {"debug": 0, "keep": 0}
    kept = []
    files = sorted({f for p in SOURCES for f in glob.glob(os.path.join(ROOT, p), recursive=True)})
    for path in files:
        s = open(path, errors="replace").read()
        edits = []
        for m in CALL.finditer(s):
            fn = m.group(1)
            lvl = "ERR" if fn.startswith("pr_err") else "WARN"
            text = first_literal(s, m.end())
            d, tag = decide(lvl, text, counts, a.rare_max)
            if d is None:
                continue
            stats[d] += 1
            if d == "keep":
                kept.append("%s\t%s\t%s\t%d" % (os.path.relpath(path, ROOT), fn, tag, counts.get(tag, 0)))
            else:
                edits.append((m.start(1), m.end(1), REPLACE[fn]))
        for m in PAL.finditer(s):
            lvl = m.group(1)
            text = first_literal(s, m.end())
            d, tag = decide(lvl if lvl == "ERR" else "WARN", text, counts, a.rare_max)
            if d is None:
                continue
            stats[d] += 1
            if d == "keep":
                kept.append("%s\tmxfs_pal_log(%s)\t%s\t%d" % (os.path.relpath(path, ROOT), lvl, tag, counts.get(tag, 0)))
            else:
                edits.append((m.start(1), m.end(1), "DEBUG"))
        if a.apply and edits:
            for st, en, rep in sorted(edits, reverse=True):
                s = s[:st] + rep + s[en:]
            open(path, "w").write(s)
    print("probe prints -> dynamic debug: %d   kept at their level: %d" % (stats["debug"], stats["keep"]))
    if a.kept:
        open(a.kept, "w").write("\n".join(sorted(kept)) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())

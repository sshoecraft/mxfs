#!/usr/bin/env python3
"""
Move named default-level prints to dynamic debug, site by site.

scripts/log_probe_levels.py decides by rule (a tag, serious wording, how often
it fired).  This one applies decisions made by hand from a measured log: each
line of the list names a fragment of one message's format string, and every
call whose format contains it and still prints at default level is rewritten
to its probe form:

    pr_warn/pr_info/pr_notice/pr_err          -> mxfs_probe
    pr_*_ratelimited / pr_*_once               -> mxfs_probe_ratelimited / _once
    mxfs_pal_log(MXFS_LOG_WARN|INFO|ERR, ...)  -> mxfs_pal_log(MXFS_LOG_DEBUG, ...)
    xfs_warn/xfs_notice/xfs_info/xfs_alert     -> mxfs_xfs_probe

A fragment names a message variant, not a tag family: "FENCECAP-OK" moves the
success line and leaves the refusal lines of the same family where they are.
Each list line may end in a tab and the number of sites the fragment must
match (default 1); a different number is an error and nothing is written.

Usage:
    scripts/log_demote_sites.py LIST            report only
    scripts/log_demote_sites.py LIST --apply    rewrite the tree
"""
import glob
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SOURCES = ["xfs/**/*.c", "xfs/*.h", "pal/**/*.c", "dlm/*.c", "mxfs_clayer/*.c"]

# Error-level prints (pr_err, xfs_alert, MXFS_LOG_ERR) are never touched:
# an error that fires routinely is a defect to fix, not a line to hide.
CALL = re.compile(r"\b(pr_(?:warn|info|notice)(?:_ratelimited|_once)?|"
                  r"xfs_(?:warn|notice|info)(?:_ratelimited)?|"
                  r"mxfs_pal_log)\s*\(")
# the level argument, plain or chosen by a condition ("rc ? MXFS_LOG_WARN :
# MXFS_LOG_INFO").  In the conditional form the less severe arm is the
# routine outcome; it is demoted, the other arm keeps its level.
PAL_PLAIN = re.compile(r"\s*MXFS_LOG_(WARN|INFO|NOTICE)\b")
PAL_COND = re.compile(r"\s*[^,;()?]*\?\s*MXFS_LOG_(\w+)\s*:\s*MXFS_LOG_(\w+)\b")
SEVERITY = {"DEBUG": 0, "INFO": 1, "NOTICE": 2, "WARN": 3, "ERR": 4}
STR = re.compile(r'"((?:\\.|[^"\\])*)"')


def fmt_literal(s, i):
    """The first run of adjacent string literals after position i, joined."""
    q = s.find('"', i)
    if q < 0 or q - i > 400:
        return "", i
    out = []
    j = q
    while True:
        m = STR.match(s, j)
        if not m:
            break
        out.append(m.group(1))
        j = m.end()
        while j < len(s) and s[j] in " \t\n\\":
            j += 1
        if s.startswith("/*", j):
            j = s.find("*/", j) + 2
            while j < len(s) and s[j] in " \t\n":
                j += 1
    return "".join(out), q


def rewrite(fn):
    if fn.startswith("xfs_"):
        return "mxfs_xfs_probe"
    if fn.endswith("_ratelimited"):
        return "mxfs_probe_ratelimited"
    if fn.endswith("_once"):
        return "mxfs_probe_once"
    return "mxfs_probe"


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    apply = "--apply" in sys.argv[2:]
    wanted = []
    for raw in open(sys.argv[1]):
        line = raw.rstrip("\n")
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        frag, _, n = line.partition("\t")
        wanted.append((frag, int(n) if n.strip() else 1))

    files = sorted({f for p in SOURCES for f in glob.glob(os.path.join(ROOT, p), recursive=True)})
    text = {f: open(f, errors="replace").read() for f in files}
    sites = []                      # (file, start, end, replacement, frag, fn)
    bad = 0
    for frag, need in wanted:
        found = []
        for f, s in text.items():
            for m in CALL.finditer(s):
                fn = m.group(1)
                lit, _ = fmt_literal(s, m.end())
                if frag not in lit:
                    continue
                if fn == "mxfs_pal_log":
                    lc = PAL_COND.match(s, m.end())
                    lp = PAL_PLAIN.match(s, m.end())
                    if lc:
                        a, b = lc.group(1), lc.group(2)
                        if a not in SEVERITY or b not in SEVERITY:
                            continue
                        arm = 1 if SEVERITY[a] < SEVERITY[b] else 2
                        if SEVERITY[lc.group(arm)] == 0 or SEVERITY[a] == SEVERITY[b]:
                            continue
                        found.append((f, lc.start(arm), lc.end(arm), "DEBUG", frag,
                                      "%s(%s arm of %s/%s)" % (fn, lc.group(arm), a, b)))
                    elif lp:
                        found.append((f, lp.start(1), lp.end(1), "DEBUG", frag, fn))
                else:
                    found.append((f, m.start(1), m.end(1), rewrite(fn), frag, fn))
        mark = "ok " if len(found) == need else "BAD"
        if len(found) != need:
            bad += 1
        where = ", ".join("%s:%d %s" % (os.path.relpath(f, ROOT), text[f].count("\n", 0, st) + 1, fn)
                          for f, st, _, _, _, fn in found)
        print("%s %d/%d  %-40s %s" % (mark, len(found), need, frag, where))
        sites.extend(found)

    print("%d fragment(s), %d site(s), %d mismatched" % (len(wanted), len(sites), bad))
    if bad or not apply:
        return 1 if bad else 0
    by_file = {}
    for f, st, en, rep, _, _ in sites:
        by_file.setdefault(f, set()).add((st, en, rep))
    for f, edits in by_file.items():
        s = text[f]
        for st, en, rep in sorted(edits, reverse=True):
            s = s[:st] + rep + s[en:]
        open(f, "w").write(s)
    print("rewrote %d site(s) in %d file(s)" % (sum(len(e) for e in by_file.values()), len(by_file)))
    return 0


if __name__ == "__main__":
    sys.exit(main())

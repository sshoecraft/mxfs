#!/usr/bin/env python3
"""Census every single-node fast path in the tree, with its enclosing function.

WHY THIS EXISTS.  mxfs_v5_dlm_is_single_node() answers "is this mount
single-node RIGHT NOW".  A large number of guards ask it when the question
they actually need answered is "has this volume ever had another node during
this mount", because that is what decides whether anybody else can still hold
a view of the metadata in hand.  The sole survivor of a peer's death or clean
departure answers yes to the first and no to the second, so every guard of the
first kind switches itself off at the moment a departed peer's residue is on
the platter and nobody is left to publish it.

mxfs_v5_dlm_sole_survivor() is the second predicate and already exists.  The
gap between how many call sites use each one is the size of the class:

    D-0904 closed this on ONE call site.  D-0949 found another, three
    campaigns later, and it had deleted 187 inode chunks in a single lap
    without ever printing a line -- because its only probe sat inside a
    branch requiring not-multi-node while itself requiring multi-node.

Reading 400 references by hand, once per session, is how a class stays open.
This script does the reading, so what a session spends its judgement on is
which of these guards is load-bearing.

WHAT IT REPORTS.  Only guards where SINGLE-NODE TAKES THE BRANCH -- i.e. where
being alone means skipping work.  A `!is_single_node()` test guards work that
only runs when peers exist; a departing peer disables that too, but the shape
is different and is reported separately under --inverted.

This is a STATIC census and it cannot tell you which guards matter.  It ranks
nothing and it decides nothing: a site is dangerous when the work it skips has
consequences that outlive the membership change (freeing metadata a departed
peer may reference, skipping validation of state a departed peer wrote,
skipping an invalidation of a cache the peer's writes made stale, whole-writing
a buffer whose slots the peer owned).  A site is fine when the work it skips is
a lock or a message that a rejoining peer would force to be re-taken anyway.
Deciding which is which is the reader's job; finding all of them is this
script's.

Usage:
    tools/sole_survivor_audit.py                 # positive guards, grouped
    tools/sole_survivor_audit.py --inverted      # !is_single_node() sites too
    tools/sole_survivor_audit.py --csv           # file,line,function,shape
"""
import argparse
import json
import os
import re
import sys

PRED = "mxfs_v5_dlm_is_single_node"
SOLE = "mxfs_v5_dlm_sole_survivor"

# A C function definition at column 0: either "name(" on its own line (the
# kernel's style, return type on the line above) or "type name(".
FUNC = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\s*\(")
SKIP_KEYWORDS = {"if", "for", "while", "switch", "return", "sizeof", "else"}


def enclosing_functions(lines):
    """Map line index -> the most recent column-0 function-ish name."""
    out = [None] * len(lines)
    cur = None
    for i, raw in enumerate(lines):
        if raw and not raw[0].isspace() and not raw.startswith(("#", "/", "*", "}")):
            m = FUNC.match(raw)
            if m and m.group(1) not in SKIP_KEYWORDS:
                cur = m.group(1)
            else:
                # "static int" / "void" on its own line: the name follows.
                bare = raw.strip()
                if bare and not bare.endswith((";", ",")) and "(" not in bare:
                    pass  # a return type; the next line carries the name
        out[i] = cur
    return out


def source_files(root):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames
                       if d not in (".git", ".ccloop", ".ccmemory", "tests",
                                    "bench", "packaging", "docs")]
        for fn in filenames:
            if fn.endswith((".c", ".h")):
                yield os.path.join(dirpath, fn)


def classify(line):
    """positive = single-node takes the branch; inverted = the opposite."""
    # Strip the negated form first so a compound test is judged on the
    # occurrence that actually decides the branch.
    if re.search(r"!\s*" + PRED, line):
        return "inverted"
    return "positive"


def follows_with_exit(lines, i):
    """Does the guard hand control back, before doing anything else?

    SCAN A FEW LINES, DO NOT JUST LOOK AT THE NEXT ONE.  A guard that has been
    instrumented reads

        if (is_single_node(...)) {
            MXFS_SOLE_SKIP_NOTE(dlm, "site");
            return;
        }

    and a next-line-only test stops seeing it the moment a probe is added --
    so adding instrumentation to a site silently removed it from this census.
    Measured: the count fell 77 -> 70 the instant seven guards were
    instrumented, which is the one direction a safety census must never move
    by accident.

    The scan stops at a closing brace or at anything that is neither a probe
    nor an exit, so a branch that does real work before returning is still not
    counted as a bare skip.
    """
    probe = re.compile(r"^(MXFS_SOLE_SKIP_NOTE|pr_warn|pr_info|pr_debug|"
                       r"printk|mxfs_pal_log|trace_|\{|/\*|\*|//)")
    for k in range(i + 1, min(i + 6, len(lines))):
        t = lines[k].strip()
        if not t:
            continue
        m = re.match(r"^(return\b[^;]*;|goto\s+\w+;|break;)", t)
        if m:
            return m.group(1)
        if t.startswith("}"):
            return ""
        if not probe.match(t):
            return ""
    return ""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=os.path.join(
        os.path.dirname(os.path.abspath(__file__)), ".."))
    ap.add_argument("--inverted", action="store_true",
                    help="also list !is_single_node() sites")
    ap.add_argument("--csv", action="store_true")
    ap.add_argument("--baseline", action="store_true",
                    help="write the reviewed site inventory and exit")
    ap.add_argument("--check", action="store_true",
                    help="exit 1 if a guard exists that the inventory does "
                         "not account for")
    ap.add_argument("--inventory", default=None)
    ap.add_argument("--classify", nargs=3, metavar=("SITE", "CLASS", "NOTE"),
                    action="append",
                    help="record a decision: SITE is 'file::function', CLASS "
                         "is epoch|durable|recovery|instrument, NOTE is the "
                         "reason. Repeatable. Writes the inventory and exits.")
    args = ap.parse_args()

    root = os.path.abspath(args.root)
    rows = []
    sole_sites = []
    for path in sorted(source_files(root)):
        try:
            lines = open(path, errors="replace").read().split("\n")
        except OSError:
            continue
        if PRED not in "\n".join(lines) and SOLE not in "\n".join(lines):
            continue
        funcs = enclosing_functions(lines)
        rel = os.path.relpath(path, root)
        for i, line in enumerate(lines):
            if SOLE in line and "bool " + SOLE not in line:
                sole_sites.append((rel, i + 1, funcs[i] or "?"))
            if PRED not in line:
                continue
            kind = classify(line)
            exit_stmt = follows_with_exit(lines, i)
            rows.append((rel, i + 1, funcs[i] or "?", kind, exit_stmt,
                         line.strip()))

    positive = [r for r in rows if r[3] == "positive"]
    inverted = [r for r in rows if r[3] == "inverted"]
    guards = [r for r in positive if r[4]]

    inv_path = args.inventory or os.path.join(
        root, "tests", "criteria", "sole_survivor_sites.json")

    # THE INVENTORY IS KEYED BY (file, function), NEVER BY LINE.  Line numbers
    # move on every unrelated edit, so a line-keyed baseline would fail on
    # noise and be switched off within a week -- which is how the previous two
    # closures of this class ended up unenforced.
    current = {}
    for r in guards:
        current["%s::%s" % (r[0], r[2])] = current.get(
            "%s::%s" % (r[0], r[2]), 0) + 1

    # THE INVENTORY IS A WORK QUEUE, NOT A TALLY.  A count alone says the class
    # is 77 wide and nothing about which of them anyone has actually thought
    # about -- which is how it stayed open through two closures.  Each site
    # carries a class and the reason, and a re-baseline PRESERVES both, so the
    # sweep survives a session boundary instead of restarting from a number.
    #
    # The classes are the ones a design-consult ruling named (sess574).  The axis is
    # NOT performance versus correctness; it is what fact makes the skipped
    # work unnecessary and what stops that fact changing mid-operation:
    #
    #   epoch        transient coordination, elidable ONLY while an exclusion
    #                against peer admission is HELD for the whole operation.
    #                A bare "am I alone" boolean is a TOCTOU observation and
    #                does not qualify.
    #   durable      the skipped work leaves state a future or rejoining peer
    #                can observe (publication, allocation/reuse validation,
    #                write masking, invalidation obligations, ownership).
    #                Maintain regardless of membership, or convert explicitly
    #                before admitting a peer.
    #   recovery     the answer depends on the DEPARTED PEER'S DISPOSITION --
    #                clean handoff, unfenced, fenced-but-unrecovered, recovered
    #                per-AG -- and not on member count at all.
    #   instrument   a probe. Skipping costs measurement, not correctness.
    #                Still worth recording: an unreachable probe is exactly how
    #                D-0949 stayed invisible for the life of the project.
    #   unclassified nobody has decided yet. The honest default.
    prior = {}
    try:
        with open(inv_path) as f:
            prior = json.load(f).get("sites", {})
    except OSError:
        prior = {}

    def merged(counts):
        """Live guards PLUS every site the inventory already knows about.

        A SITE THAT IS CONVERTED MUST NOT VANISH FROM THE QUEUE.  Rewriting a
        guard so it is no longer a bare single-node skip -- adding a nested
        decision, or removing the membership test altogether -- drops it out of
        the census, and a live-only inventory would then silently discard the
        classification and the reasoning with it.  The two sites this campaign
        understands best, mxfs_submit_partial_inode_write and
        mxfs_dialloc_two_phase, left the census the moment they were touched.
        Losing their records would mean the next session re-derives them from
        nothing, which is exactly how this class survived being closed twice.

        guards == 0 means "no longer a bare skip here"; the class and the note
        stay, so the file remains the record of what was decided and why.
        """
        out = {}
        for k in sorted(set(counts) | set(prior)):
            was = prior.get(k)
            was = was if isinstance(was, dict) else {}
            out[k] = {
                "guards": counts.get(k, 0),
                "class": was.get("class", "unclassified"),
                "note": was.get("note", ""),
            }
        return out

    if args.classify:
        valid = ("epoch", "durable", "recovery", "instrument", "unclassified")
        sites = merged(current)
        for site, cls, note in args.classify:
            if cls not in valid:
                print("FAIL '%s' is not a class (%s)" % (cls, "|".join(valid)))
                return 1
            # A CLASSIFICATION RECORDED AGAINST A TYPO IS WORSE THAN NONE: it
            # reads as a decision while the real guard stays unclassified.  But
            # the census's own definition of a "guard" is narrow -- a BARE
            # single-node skip -- and the sites most worth classifying include
            # ones since converted into a nested decision, or with the
            # membership test removed outright, which are precisely the ones
            # carrying the most reasoning.  So the existence check is against
            # the TREE, not against the census: the file must exist and must
            # contain that function name.
            if site not in sites and site not in current:
                if "::" not in site:
                    print("FAIL '%s' is not 'file::function'" % site)
                    return 1
                sf, fn = site.split("::", 1)
                try:
                    body = open(os.path.join(root, sf), errors="replace").read()
                except OSError:
                    print("FAIL '%s' — no such file in this tree" % sf)
                    return 1
                if fn not in body:
                    print("FAIL '%s' does not appear in %s — check the "
                          "spelling against --csv" % (fn, sf))
                    return 1
            sites.setdefault(site, {"guards": current.get(site, 0),
                                    "class": "unclassified", "note": ""})
            sites[site]["class"] = cls
            sites[site]["note"] = note
        prior = {k: v for k, v in sites.items()}
        args.baseline = True

    if args.baseline:
        os.makedirs(os.path.dirname(inv_path), exist_ok=True)
        sites = merged(current)
        unclassified = sum(1 for v in sites.values()
                           if v["class"] == "unclassified" and v["guards"] > 0)
        with open(inv_path, "w") as f:
            json.dump({
                "note": ("Reviewed inventory of single-node fast paths that "
                         "SKIP WORK. A guard here is not thereby safe; it is "
                         "thereby KNOWN. Regenerate ONLY after classifying the "
                         "new sites -- re-baselining to clear a red is the "
                         "same act as widening a timeout to make a test pass."),
                "classes": {
                    "epoch": "transient coordination, elidable only under a HELD exclusion against peer admission",
                    "durable": "leaves state a future or rejoining peer can observe; maintain regardless of membership",
                    "recovery": "depends on the departed peer's disposition, not on member count",
                    "instrument": "a probe; skipping costs measurement, not correctness",
                    "unclassified": "nobody has decided yet",
                },
                "generated": "tools/sole_survivor_audit.py --baseline",
                "total_guards": len(guards),
                "unclassified_sites": unclassified,
                "sites": sites,
            }, f, indent=2, sort_keys=True)
            f.write("\n")
        print("wrote %s: %d guards across %d (file, function) sites, "
              "%d still unclassified"
              % (inv_path, len(guards), len(current), unclassified))
        return 0

    if args.check:
        try:
            with open(inv_path) as f:
                base = json.load(f).get("sites", {})
        except OSError:
            # FAIL CLOSED.  A missing inventory is not an empty one: it means
            # the gate cannot answer, and a gate that passes when it cannot
            # answer is the failure mode this whole class is made of.
            print("FAIL no inventory at %s — the census gate cannot answer, "
                  "so it refuses" % inv_path)
            return 1
        def basecount(v):
            return v.get("guards", 0) if isinstance(v, dict) else v

        added, grown = [], []
        for k, n in sorted(current.items()):
            if k not in base:
                added.append((k, n))
            elif n > basecount(base[k]):
                grown.append((k, basecount(base[k]), n))
        unclassified = sum(1 for k, v in base.items()
                           if isinstance(v, dict)
                           and v.get("class", "unclassified") == "unclassified"
                           and k in current)
        gone = [k for k in sorted(base) if k not in current]
        for k, n in added:
            print("NEW    %s  (%d guard(s)) — not in the reviewed inventory" % (k, n))
        for k, b, n in grown:
            print("GREW   %s  %d -> %d" % (k, b, n))
        for k in gone:
            print("note   %s is gone (converted or removed)" % k)
        if added or grown:
            print("FAIL %d new site(s), %d grown — a single-node fast path was "
                  "added without being classified. Classify it, then re-run "
                  "with --baseline." % (len(added), len(grown)))
            return 1
        print("OK %d guards, all accounted for by %s (unclassified=%d)"
              % (len(guards), inv_path, unclassified))
        return 0

    if args.csv:
        print("file,line,function,shape,exit")
        for r in guards:
            print("%s,%d,%s,%s,%s" % (r[0], r[1], r[2], r[3],
                                      r[4].replace(",", ";")))
        return 0

    print("=== single-node fast paths that SKIP WORK when the node is alone ===")
    print("    (the sole survivor of a departure takes every one of these)")
    print()
    byfunc = {}
    for r in guards:
        byfunc.setdefault((r[0], r[2]), []).append(r)
    for (f, fn), rs in sorted(byfunc.items()):
        print("  %s  %s()" % (f, fn))
        for r in rs:
            print("      :%-6d -> %s" % (r[1], r[4]))
    print()
    print("counts: %d guards that skip work, out of %d %s() references"
          % (len(guards), len(rows), PRED))
    print("        %d references to %s()" % (len(sole_sites), SOLE))
    print()
    print("A guard is DANGEROUS when the work it skips has consequences that")
    print("outlive the membership change.  It is FINE when the work it skips is")
    print("a lock or a message a rejoining peer would force to be re-taken.")
    print("This script does not and cannot make that call.")

    if args.inverted:
        print()
        print("=== !%s() sites (work that runs ONLY with peers) ===" % PRED)
        byfunc = {}
        for r in inverted:
            byfunc.setdefault((r[0], r[2]), []).append(r[1])
        for (f, fn), ls in sorted(byfunc.items()):
            print("  %s  %s()  lines %s" % (f, fn, ",".join(str(x) for x in ls)))
        print()
        print("counts: %d inverted references" % len(inverted))
    return 0


if __name__ == "__main__":
    sys.exit(main())

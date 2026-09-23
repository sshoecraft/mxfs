#!/usr/bin/env python3
"""Append to a defect record's evidence or next-step without retyping it.

`defects.py update -w/-n` REPLACES the field.  Every session that has
measured one more thing about a long-lived record therefore had to re-send
the whole accumulated text, and the cost of that is that sooner or later
somebody sends a shortened version and a measurement disappears.

This reads the current text out of the queue, appends the new text to it,
and hands the result back to `defects.py update`, which stays the only
writer of the JSON.  The old text is never retyped and so cannot be lost.

    tools/defect_append.py <id-or-substring> --evidence "what was measured"
    tools/defect_append.py <id-or-substring> --next "what to do now"
    tools/defect_append.py <id-or-substring> --next-replace "..."   # deliberate

`--evidence` is append-only on purpose: evidence accumulates.  The
next-step is the one field a new measurement legitimately REPLACES, so it
has both forms and neither is the default you get by accident.
"""
import argparse
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
QUEUE = os.path.join(os.path.dirname(HERE), "data", "defects.json")
DEFECTS = os.path.join(HERE, "defects.py")


def load(ident):
    with open(QUEUE) as fh:
        data = json.load(fh)
    entries = data["defects"] if isinstance(data, dict) else data
    hits = [e for e in entries if e.get("id") == ident]
    if not hits:
        hits = [e for e in entries if ident.lower() in e.get("id", "").lower()]
    if not hits:
        sys.exit("defect_append: no record matches %r" % ident)
    if len(hits) > 1:
        sys.exit("defect_append: %r matches %d records:\n  %s"
                 % (ident, len(hits), "\n  ".join(e["id"] for e in hits)))
    return hits[0]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("id")
    ap.add_argument("--evidence", help="text appended to the evidence field")
    ap.add_argument("--next", dest="nxt", help="text appended to the next step")
    ap.add_argument("--next-replace", dest="nxt_replace",
                    help="text that REPLACES the next step")
    ap.add_argument("--sep", default=" ===== ",
                    help="separator placed between the old text and the new")
    args = ap.parse_args()
    if not (args.evidence or args.nxt or args.nxt_replace):
        sys.exit("defect_append: nothing to append; pass --evidence, --next or --next-replace")
    if args.nxt and args.nxt_replace:
        sys.exit("defect_append: --next and --next-replace are exclusive")

    entry = load(args.id)
    cmd = [sys.executable, DEFECTS, "update", entry["id"]]
    if args.evidence:
        old = (entry.get("evidence") or "").strip()
        cmd += ["-w", (old + args.sep + args.evidence) if old else args.evidence]
    if args.nxt:
        old = (entry.get("next") or "").strip()
        cmd += ["-n", (old + args.sep + args.nxt) if old else args.nxt]
    if args.nxt_replace:
        cmd += ["-n", args.nxt_replace]
    raise SystemExit(subprocess.call(cmd))


if __name__ == "__main__":
    main()

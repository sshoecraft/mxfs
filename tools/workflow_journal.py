#!/usr/bin/env python3
"""Extract agent return values from a Claude Code Workflow journal.

A Workflow's notification carries its return value inline and truncates it when
large — a 10-agent run produced 372k chars and lost most of it. The journal on
disk holds every agent's FULL return value, one JSON object per line, so it is
the only complete record. This reads that file and prints chosen fields, so the
selection is mechanical and visible rather than a model deciding what survives.

Every truncation prints the pre-truncation length, because a silently shortened
field reads as a complete one.

Usage:
  workflow_journal.py list <journal.jsonl>
      One line per entry: index, type, label, result field names.

  workflow_journal.py show <journal.jsonl> <index> [field ...] [--cap N]
      Print the named fields of one result entry (all fields if none named).

  workflow_journal.py field <journal.jsonl> <field> [--cap N]
      Print that field from every result entry that has it.

--cap N truncates each scalar field to N chars (default 4000, 0 = no cap).
Lists and dicts are pretty-printed whole unless --cap applies to their rendering.
"""

import json
import sys

DEFAULT_CAP = 4000


def load(path):
    """Yield (index, parsed-dict) for each non-blank line, skipping bad JSON."""
    entries = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for i, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                entries.append((i, json.loads(line)))
            except json.JSONDecodeError as exc:
                print("line %d: UNPARSEABLE (%s)" % (i, exc), file=sys.stderr)
    return entries


def labels_by_order(entries):
    """Map each result entry to the started-entry label that preceded it.

    The journal records a `started` line per agent carrying its label, then a
    `result` line per agent carrying no label. Within a phase the results arrive
    in completion order, not launch order, so this pairing is POSITIONAL and can
    mislabel two agents of the same phase. It is printed as a hint, never used to
    select content.
    """
    pending, out = [], {}
    for idx, d in entries:
        kind = d.get("type")
        if kind == "started":
            pending.append(d.get("label") or "")
        elif kind == "result":
            out[idx] = pending.pop(0) if pending else ""
    return out


def render(value, cap):
    if isinstance(value, str):
        text = value
    else:
        text = json.dumps(value, indent=2, ensure_ascii=False)
    if cap and len(text) > cap:
        return "%s\n    [... truncated: %d of %d chars shown]" % (
            text[:cap], cap, len(text))
    return text


def results(entries):
    return [(i, d) for i, d in entries if d.get("type") == "result"]


def cmd_list(entries):
    hints = labels_by_order(entries)
    for idx, d in entries:
        res = d.get("result")
        if isinstance(res, dict):
            shape = ",".join(sorted(res.keys()))
        elif isinstance(res, str):
            shape = "<str %d chars>" % len(res)
        else:
            shape = ""
        label = d.get("label") or hints.get(idx, "")
        print("%-3d %-9s %-40s %s" % (idx, d.get("type", ""), label, shape))


def cmd_show(entries, index, fields, cap):
    hints = labels_by_order(entries)
    for idx, d in results(entries):
        if idx != index:
            continue
        res = d.get("result")
        print("=== entry %d  (label hint: %s) ===" % (idx, hints.get(idx, "?")))
        if not isinstance(res, dict):
            print(render(res, cap))
            return 0
        for key in (fields or sorted(res.keys())):
            if key not in res:
                print("-- %s: ABSENT" % key)
                continue
            print("-- %s --" % key)
            print(render(res[key], cap))
            print()
        return 0
    print("no result entry at index %d" % index, file=sys.stderr)
    return 1


def cmd_field(entries, field, cap):
    hints = labels_by_order(entries)
    found = 0
    for idx, d in results(entries):
        res = d.get("result")
        if not isinstance(res, dict) or field not in res:
            continue
        found += 1
        print("=== entry %d  (label hint: %s)  field=%s ===" % (
            idx, hints.get(idx, "?"), field))
        print(render(res[field], cap))
        print()
    if not found:
        print("field %r present in 0 of %d result entries" % (
            field, len(results(entries))), file=sys.stderr)
        return 1
    print("[%s present in %d of %d result entries]" % (
        field, found, len(results(entries))))
    return 0


def main(argv):
    argv = list(argv[1:])
    cap = DEFAULT_CAP
    if "--cap" in argv:
        pos = argv.index("--cap")
        try:
            cap = int(argv[pos + 1])
        except (IndexError, ValueError):
            print("--cap needs an integer", file=sys.stderr)
            return 2
        del argv[pos:pos + 2]

    if len(argv) < 2:
        print(__doc__)
        return 2

    mode, path = argv[0], argv[1]
    rest = argv[2:]
    entries = load(path)
    if not entries:
        print("no entries in %s" % path, file=sys.stderr)
        return 1

    if mode == "list":
        cmd_list(entries)
        return 0
    if mode == "show":
        if not rest:
            print("show needs an index", file=sys.stderr)
            return 2
        return cmd_show(entries, int(rest[0]), rest[1:], cap)
    if mode == "field":
        if not rest:
            print("field needs a field name", file=sys.stderr)
            return 2
        return cmd_field(entries, rest[0], cap)

    print("unknown mode %r" % mode, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))

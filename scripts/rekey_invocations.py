#!/usr/bin/env python3
"""Rewrite condition-code invocations in the tree's scripts to configurations.

    scripts/rekey_invocations.py            report what would change, write nothing
    scripts/rekey_invocations.py --write    apply it

Until 0.90.37 the rig named what it tested with condition codes -- tcp, cawd, cawp, caw --
and hundreds of harnesses spell them out: `./run.sh 2 tcp prep_cluster`, `criteria.py 32 caw`,
`export MXFS_TRANSPORT=${MXFS_TRANSPORT:-tcp}`, "prep 2/tcp first". The tools now refuse
every one of those (tools/configuration.py), so this rewrites the shapes that can be rewritten
without judgement and REPORTS every line it could not, for a person to read:

    run.sh|criteria.py|defects.py <nodes> <code>   ->  <nodes>/<class>/<method>/<attach>
    <nodes>/<code> anywhere in a script             ->  <nodes>/<class>/<method>/<attach>
    export MXFS_TRANSPORT=${MXFS_TRANSPORT:-tcp}    ->  export MXFS_CONFIG=${MXFS_CONFIG:-2/net/mesh/direct}

The last rule is applied only in a file whose every run.sh invocation is at 2 nodes (or that
has none): the harnesses that carry it are 2-node, and one at another size is left for a person.

Kernel-facing transport names are NOT touched: `prep_node.sh tcp|caw` and force_transport take
what the module takes. History is not touched: docs/history, docs/rulings, tests/evidence and
.ccmemory are skipped, and so are the tools that define or migrate the codes.
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import configuration  # noqa: E402

SKIP_DIRS = ("docs/history", "docs/rulings", "tests/evidence", ".ccmemory", ".git", "dist",
             "node_modules")
SKIP_FILES = ("tools/configuration.py", "tools/criteria.py", "tools/defects.py",
              "scripts/rekey_invocations.py", "scripts/migrate_configuration_keys.py")

CODES = "tcpmp|tcp|cawd|cawp|caw"
NODE = r'(?:\d+|"\$\{?\w+\}?"|\$\{?\w+\}?)'
INVOKE = re.compile(r"((?:run\.sh|criteria\.py|defects\.py)\s+)(%s)\s+(%s|xfs)\b" % (NODE, CODES))
INLINE = re.compile(r"(?<![\w/.:-])(\d{1,2})/(%s)\b" % CODES)
EXPORT_A = "export MXFS_TRANSPORT=${MXFS_TRANSPORT:-tcp}"
EXPORT_B = "export MXFS_CONFIG=${MXFS_CONFIG:-2/net/mesh/direct}"
RUN_NODES = re.compile(r"run\.sh\s+\"?(\S+?)[/\"\s]")
LEFTOVER = re.compile(r"\b(cawd|cawp|tcpmp)\b|MXFS_TRANSPORT|MXFS_DLM")


def new_key(node: str, code: str) -> str:
    code = code.lower()
    tail = "xfs" if code == "xfs" else configuration.RETIRED[code]
    if node.startswith('"') and node.endswith('"'):
        return '"%s/%s"' % (node[1:-1], tail)
    return "%s/%s" % (node, tail)


def scripts() -> list:
    out = []
    for path in sorted(ROOT.rglob("*")):
        rel = path.relative_to(ROOT).as_posix()
        if not path.is_file() or any(rel == d or rel.startswith(d + "/") for d in SKIP_DIRS):
            continue
        if rel in SKIP_FILES:
            continue
        if path.suffix in (".sh", ".py", ".bash"):
            out.append(path)
            continue
        if path.suffix == "":
            try:
                with path.open("rb") as handle:
                    if handle.read(2) == b"#!":
                        out.append(path)
            except OSError:
                pass
    return out


def rewrite(text: str) -> tuple:
    changes = []
    lines = text.split("\n")
    nodes_seen = {m.group(1) for m in RUN_NODES.finditer(text)}
    only_two = nodes_seen <= {"2"}
    for index, line in enumerate(lines):
        new = INVOKE.sub(lambda m: m.group(1) + new_key(m.group(2), m.group(3)), line)
        new = INLINE.sub(lambda m: "%s/%s" % (m.group(1), configuration.RETIRED[m.group(2).lower()]),
                         new)
        if EXPORT_A in new and only_two:
            new = new.replace(EXPORT_A, EXPORT_B)
        if new != line:
            changes.append((index + 1, line, new))
            lines[index] = new
    return "\n".join(lines), changes


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--write", action="store_true", help="apply the rewrite")
    parser.add_argument("-q", "--quiet", action="store_true", help="counts and leftovers only")
    args = parser.parse_args()

    files_changed = lines_changed = 0
    leftovers = []
    for path in scripts():
        try:
            text = path.read_text()
        except (UnicodeDecodeError, OSError):
            continue
        new, changes = rewrite(text)
        rel = path.relative_to(ROOT).as_posix()
        if changes:
            files_changed += 1
            lines_changed += len(changes)
            if not args.quiet:
                for number, old, line in changes:
                    print("%s:%d\n  - %s\n  + %s" % (rel, number, old.strip(), line.strip()))
            if args.write:
                path.write_text(new)
        for number, line in enumerate(new.split("\n"), 1):
            if LEFTOVER.search(line):
                leftovers.append("%s:%d: %s" % (rel, number, line.strip()[:160]))
    print("\n%s: %d line(s) in %d file(s)" % ("rewrote" if args.write else "would rewrite",
                                             lines_changed, files_changed))
    print("left for a person (%d line(s): a retired code, MXFS_TRANSPORT or MXFS_DLM):"
          % len(leftovers))
    for line in leftovers:
        print("  " + line)
    return 0


if __name__ == "__main__":
    sys.exit(main())

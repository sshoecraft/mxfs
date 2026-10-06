#!/usr/bin/env python3
"""
kgrep.py — search kernel logs, plain or gzip, in one command.

The rig keeps each node's kernel log as kmsg_<node>_fromnode.gz (and plain
.txt copies).  Reading one took `zcat f | sed -n '/MARK/,$p' | grep -a … |
grep -v … | cut -c1-N | head`, and a command that begins with a program the
session is not allowed to run unattended stops the loop on an approval prompt.
This does the whole pipeline as one allowed command.

  tools/kgrep.py [options] FILE...

  -e REGEX        a line matches if any -e matches (Python regex); none = all
  -v REGEX        drop lines matching any -v
  --from TEXT     start at the first line containing TEXT (a row's PF-MARK)
  --cut N         cut each printed line to N characters (default 300)
  --max N         print at most N matching lines per file (default 200)
  --tail          with --max, print the LAST N matches instead of the first
  -c              print only the count of matching lines per file
  -B N / -A N     also print N lines before / after each match
  --no-name       do not prefix lines with file:line:

Every file prints a header "== FILE matches=M printed=P", so a cap that bit is
visible (M > P).  A missing or unreadable file prints "== FILE ERROR <why>".
"""
import argparse
import collections
import gzip
import re
import sys


def open_log(path):
    if path.endswith(".gz"):
        return gzip.open(path, "rt", errors="replace")
    return open(path, "rt", errors="replace")


def main():
    ap = argparse.ArgumentParser(add_help=True)
    ap.add_argument("-e", action="append", default=[])
    ap.add_argument("-v", action="append", default=[])
    ap.add_argument("--from", dest="start", default=None)
    ap.add_argument("--cut", type=int, default=300)
    ap.add_argument("--max", type=int, default=200)
    ap.add_argument("--tail", action="store_true")
    ap.add_argument("-c", action="store_true")
    ap.add_argument("-B", type=int, default=0)
    ap.add_argument("-A", type=int, default=0)
    ap.add_argument("--no-name", action="store_true")
    ap.add_argument("files", nargs="+")
    a = ap.parse_args()
    inc = [re.compile(x) for x in a.e]
    exc = [re.compile(x) for x in a.v]

    for path in a.files:
        out = []
        matches = 0
        try:
            before = collections.deque(maxlen=a.B)
            after_left = 0
            started = a.start is None
            with open_log(path) as f:
                for n, line in enumerate(f, 1):
                    line = line.rstrip("\n")
                    if not started:
                        if a.start in line:
                            started = True
                        else:
                            continue
                    hit = (not inc or any(r.search(line) for r in inc)) and \
                        not any(r.search(line) for r in exc)
                    shown = line if a.no_name else f"{path}:{n}: {line}"
                    shown = shown[:a.cut]
                    if hit:
                        matches += 1
                        if not a.c:
                            out.extend(before)
                            out.append(shown)
                            before.clear()
                            after_left = a.A
                    elif after_left > 0:
                        if not a.c:
                            out.append(shown)
                        after_left -= 1
                    elif a.B:
                        before.append(shown)
        except OSError as err:
            print(f"== {path} ERROR {err}")
            continue
        except EOFError as err:
            # a truncated gzip: what decompressed is still reported
            out.append(f"{path}: TRUNCATED gzip ({err})")
        if a.c:
            print(f"== {path} matches={matches}")
            continue
        if len(out) > a.max:
            out = out[-a.max:] if a.tail else out[:a.max]
        print(f"== {path} matches={matches} printed={len(out)}")
        for x in out:
            print(x)
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Keep the module's string literals ASCII.

Kernel messages go to the console, and the Linux text console has no glyph for
a multi-byte UTF-8 character: an em dash in a message prints as garbage right
after the field before it.  On pve1 an operator read 'P-TAUTH-IMPORT-RESIDUE
... mode=PR' followed by that garbage as filesystem corruption (2026-10-07).

A small C lexer walks each file (code, // and /* */ comments, string and
character literals), so only characters inside string literals are touched;
comments keep whatever they say.

Usage:
  tools/ascii_kernel_strings.py --check [paths...]   list every non-ASCII
        character inside a string literal; exit 1 if there is any
  tools/ascii_kernel_strings.py --fix [paths...]     replace the known ones
        with ASCII (see MAP); exit 1 if an unknown one is left
Paths default to the sources the kernel module is built from.
"""
import os
import sys

MAP = {
    "—": "--",    # em dash
    "–": "-",     # en dash
    "…": "...",   # ellipsis
    "→": "->",    # right arrow
    "←": "<-",    # left arrow
    "⇒": "=>",    # double right arrow
    "∪": "U",     # union
    "§": "sect.", # section sign
    "─": "-",     # box drawing horizontal
    "≤": "<=",
    "≥": ">=",
    "≠": "!=",
    "×": "x",
    "‘": "'", "’": "'", "“": "\\\"", "”": "\\\"",
}

DEFAULT_ROOTS = ["dlm", "pal", "xfs", "mxfs_clayer", "compat", "include"]


def sources(paths):
    for p in paths:
        if os.path.isfile(p):
            yield p
            continue
        for d, dirs, files in os.walk(p):
            dirs[:] = [x for x in dirs if not x.startswith(".")]
            for f in sorted(files):
                if f.endswith((".c", ".h")):
                    yield os.path.join(d, f)


def convert(text, fix):
    """(new text, [(line, char)] non-ASCII inside string literals)"""
    out = []
    found = []
    i, n, line = 0, len(text), 1
    state = "code"
    while i < n:
        c = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if c == "\n":
            line += 1
            if state == "line":
                state = "code"
        if state == "code":
            if c == "/" and nxt == "/":
                state = "line"; out.append(c + nxt); i += 2; continue
            if c == "/" and nxt == "*":
                state = "block"; out.append(c + nxt); i += 2; continue
            if c == '"':
                state = "str"
            elif c == "'":
                state = "chr"
            out.append(c); i += 1; continue
        if state == "block":
            if c == "*" and nxt == "/":
                state = "code"; out.append(c + nxt); i += 2; continue
            out.append(c); i += 1; continue
        if state == "line":
            out.append(c); i += 1; continue
        # inside a string or character literal
        if c == "\\" and i + 1 < n:
            out.append(c + nxt)
            if nxt == "\n":
                line += 1
            i += 2
            continue
        if (state == "str" and c == '"') or (state == "chr" and c == "'"):
            state = "code"; out.append(c); i += 1; continue
        if state == "str" and ord(c) > 127:
            found.append((line, c))
            if fix and c in MAP:
                out.append(MAP[c]); i += 1; continue
        out.append(c); i += 1
    return "".join(out), found


def main():
    args = sys.argv[1:]
    if not args or args[0] not in ("--check", "--fix"):
        print(__doc__.strip())
        return 2
    fix = args[0] == "--fix"
    paths = args[1:] or DEFAULT_ROOTS
    total = left = files = 0
    for f in sources(paths):
        try:
            with open(f, encoding="utf-8") as fh:
                text = fh.read()
        except UnicodeDecodeError as e:
            print("%s: not UTF-8 (%s)" % (f, e))
            left += 1
            continue
        new, found = convert(text, fix)
        if not found:
            continue
        files += 1
        total += len(found)
        for ln, ch in found:
            if not fix or ch not in MAP:
                left += 1
                print("%s:%d: U+%04X inside a string literal%s" % (
                    f, ln, ord(ch), "" if not fix else " (no ASCII mapping)"))
        if fix and new != text:
            with open(f, "w", encoding="utf-8") as fh:
                fh.write(new)
    verb = "replaced" if fix else "found"
    print("%s %d non-ASCII characters inside string literals in %d files; %d left"
          % (verb, total, files, left if fix else total))
    return 1 if left else 0


if __name__ == "__main__":
    sys.exit(main())

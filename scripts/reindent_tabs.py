#!/usr/bin/env python3
"""
Re-indent C files written with 4-space levels to kernel style: one tab per
level, continuation lines keeping their offset from the line they continue.

    scripts/reindent_tabs.py [--check] FILE...

Only leading whitespace changes, and only on lines indented with spaces
alone; no line is added or removed.  A line that starts a statement (the
previous code line ended in ; { } or :, or was blank, a directive or a
comment's end) is placed by its level, 4 columns to a tab.  A line indented
deeper than the one above it continues that line and keeps the same offset
from it, so arguments stay aligned under their open parenthesis.  Verify a
run by building before and after and comparing the objects' non-debug
sections: they must be identical.
"""
import re
import sys


def cols(ws):
    c = 0
    for ch in ws:
        c = (c // 8 + 1) * 8 if ch == "\t" else c + 1
    return c


def balanced(code):
    code = re.sub(r'"(?:\\.|[^"\\])*"', '""', code)
    code = re.sub(r"'(?:\\.|[^'\\])'", "''", code)
    return code.count("(") == code.count(")")


def render(n):
    return "\t" * (n // 8) + " " * (n % 8)


def reindent(src):
    out = []
    prev_old = prev_new = 0
    prev_ends_stmt = True
    in_comment = False
    stmt = ""
    for line in src.split("\n"):
        m = re.match(r"^([ \t]*)(.*)$", line)
        ws, body = m.group(1), m.group(2)
        if not body:
            out.append("" if not ws or ws.strip("\t ") == "" else line)
            prev_ends_stmt = True if not in_comment else prev_ends_stmt
            continue
        old = cols(ws)
        if "\t" in ws or not ws:
            new = old          # tab-led or flush-left: left as it is
        elif prev_ends_stmt or old <= prev_old:
            new = (old // 4) * 8 + old % 4
            if not prev_ends_stmt and old == prev_old:
                new = prev_new
        else:
            new = prev_new + (old - prev_old)
        out.append(render(new) + body if ws else body)
        prev_old, prev_new = old, new
        # does this line end a statement?
        code = re.sub(r"/\*.*?\*/", "", body)
        code = re.sub(r"//.*$", "", code).rstrip()
        if in_comment:
            if "*/" in body:
                in_comment = False
                prev_ends_stmt = True
            continue
        if "/*" in code and "*/" not in code[code.find("/*"):]:
            in_comment = True
            prev_ends_stmt = True
            continue
        stmt = (stmt + " " + code).strip()
        # a brace-less control header's body is a new level, not a
        # continuation: "if (x)" then "break;" -- the header may span lines
        prev_ends_stmt = (not code or code.startswith("#") or
                          (code.endswith(";") and balanced(stmt)) or
                          code.endswith(("{", "}")) or
                          bool(re.match(r"(?:case\b.*|default|[A-Za-z_]\w*)\s*:$", code)) or
                          code.endswith("*/") or
                          bool(re.match(r"(?:\}\s*)?(?:else\b|do\b|(?:if|for|while|switch|else\s+if)\s*\(.*\)$)", stmt) and
                               balanced(stmt)))
        if prev_ends_stmt:
            stmt = ""
    return "\n".join(out)


def main():
    args = sys.argv[1:]
    check = "--check" in args
    files = [a for a in args if a != "--check"]
    changed = 0
    for f in files:
        s = open(f).read()
        new = reindent(s)
        if new.count("\n") != s.count("\n"):
            sys.stderr.write("%s: line count would change; left alone\n" % f)
            continue
        if new != s:
            changed += 1
            if not check:
                open(f, "w").write(new)
    print("%d file(s) %s" % (changed, "would change" if check else "re-indented"))
    return 1 if (check and changed) else 0


if __name__ == "__main__":
    sys.exit(main())

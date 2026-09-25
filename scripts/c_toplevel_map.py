#!/usr/bin/env python3
"""
Map every top-level item of one C file: functions, declarations, macros,
preprocessor conditionals, module parameters and exports, each with its line
range, the names it defines and the identifiers it references.

Written to plan and check the split of xfs/xfs_mxfs_dlm.c, and kept because a
split is only as safe as the map it was planned from.

Usage:
    scripts/c_toplevel_map.py FILE            JSON map on stdout
    scripts/c_toplevel_map.py FILE --summary  one line per item

An item's range starts on the line after the previous item ends, so the
comment and blank lines above a definition travel with it.
"""
import json
import re
import sys

KEYWORDS = set("""
auto break case char const continue default do double else enum extern float for
goto if inline int long register restrict return short signed sizeof static
struct switch typedef union unsigned void volatile while bool true false NULL
__always_inline noinline __maybe_unused __init __exit __user __iomem __force
__attribute__ typeof __typeof__ asm __asm__ likely unlikely
""".split())

IDENT = re.compile(r"[A-Za-z_]\w*")


def blank(text):
    """Spaces for every character except newlines and the backslash that
    continues a preprocessor line, so a multi-line #define stays one line."""
    return re.sub(r"[^\n\\]|\\(?!\n)", " ", text)


def blank_comments_and_strings(src):
    """Replace comments, string and char literals with spaces, keeping newlines."""
    out = []
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        if c == "/" and i + 1 < n and src[i + 1] == "*":
            j = src.find("*/", i + 2)
            j = n if j < 0 else j + 2
            out.append(blank(src[i:j]))
            i = j
        elif c == "/" and i + 1 < n and src[i + 1] == "/":
            j = src.find("\n", i)
            j = n if j < 0 else j
            out.append(" " * (j - i))
            i = j
        elif c in "\"'":
            j = i + 1
            while j < n and src[j] != c:
                if src[j] == "\\":
                    j += 1
                elif src[j] == "\n":
                    break
                j += 1
            j = min(j + 1, n)
            out.append(c + blank(src[i + 1:j - 1]) + (c if j - 1 > i else ""))
            i = j
        else:
            out.append(c)
            i += 1
    return "".join(out)


def comment_open_at_eol(raw):
    """For each line, whether a /* comment is still open at its end."""
    out = []
    i, n, incom, instr = 0, len(raw), False, None
    while i < n:
        c = raw[i]
        if c == "\n":
            out.append(incom)
            instr = None if instr else instr
        elif incom:
            if c == "*" and i + 1 < n and raw[i + 1] == "/":
                incom = False
                i += 1
        elif instr:
            if c == "\\":
                i += 1
            elif c == instr:
                instr = None
        elif c == "/" and i + 1 < n and raw[i + 1] == "*":
            incom = True
            i += 1
        elif c == "/" and i + 1 < n and raw[i + 1] == "/":
            j = raw.find("\n", i)
            i = (n if j < 0 else j) - 1
        elif c in "\"'":
            instr = c
        i += 1
    out.append(incom)
    return out


def scan(path):
    raw = open(path, errors="replace").read()
    clean = blank_comments_and_strings(raw)
    lines = clean.split("\n")
    openc = comment_open_at_eol(raw)
    rawlines = raw.split("\n")
    items = []
    depth = 0
    cur_start = None          # first code line of the current item
    prev_end = 0              # last line of the previous item
    buf = []
    ln = 0
    cond = []

    def close(end_line, text, kind_hint=None):
        nonlocal prev_end, cur_start, buf, ln
        # a comment that starts after the item's last token belongs to it
        while end_line <= len(openc) and openc[end_line - 1]:
            end_line += 1
        ln = max(ln, end_line - 1)
        items.append({"start": prev_end + 1, "code_start": cur_start, "end": end_line,
                      "text": text, "hint": kind_hint})
        prev_end = end_line
        cur_start = None
        buf = []

    while ln < len(lines):
        line = lines[ln]
        lno = ln + 1
        stripped = line.strip()
        if depth == 0 and not buf and stripped.startswith("#"):
            # preprocessor line, with continuations
            text = [line]
            end = lno
            while text[-1].rstrip().endswith("\\") and end < len(lines):
                text.append(lines[end])
                end += 1
            cur_start = lno
            close(end, "\n".join(text), "pp")
            ln = prev_end
            continue
        if depth == 0 and not buf and not stripped:
            ln += 1
            continue
        # code line
        if cur_start is None:
            cur_start = lno
        buf.append(line)
        # Alternative #if/#else branches each open or close their own
        # braces; count only the first branch of each conditional.
        pp = re.match(r"\s*#\s*(if|ifdef|ifndef|elif|else|endif)\b", line)
        if pp:
            d = pp.group(1)
            if d.startswith("if"):
                cond.append([depth, None])
            elif d in ("elif", "else") and cond:
                if cond[-1][1] is None:
                    cond[-1][1] = depth
                depth = cond[-1][0]
            elif d == "endif" and cond:
                top = cond.pop()
                if top[1] is not None:
                    depth = top[1]
            ln += 1
            continue
        for ch in line:
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
        if depth == 0:
            text = "\n".join(buf)
            t = text.rstrip()
            if t.endswith(";"):
                close(lno, text)
            elif t.endswith("}") and "{" in text:
                # function body or a braced initializer that ends with "};" on a later line
                nxt = lines[ln + 1].strip() if ln + 1 < len(lines) else ""
                # a braced initializer ("x = { ... }") waits for its ';'; a
                # function body does not -- only "=" before the first brace
                # makes it an initializer
                if re.match(r"^\)?\s*;", nxt) or ("=" in text[:text.find("{")] and not t.endswith("};")):
                    pass  # wait for the terminating ';'
                else:
                    close(lno, text)
            elif re.match(r"^\s*[A-Z_][A-Z0-9_]*\s*\(.*\)\s*$", t) and "{" not in t:
                close(lno, text)   # a macro invocation without a trailing ';'
        ln += 1
    if buf:
        close(len(lines), "\n".join(buf))
    # classify
    for it in items:
        t = it["text"]
        head = t[: t.find("{")] if "{" in t else t
        it["static"] = bool(re.match(r"\s*static\b", t))
        it["names"] = []
        if it["hint"] == "pp":
            m = re.match(r"\s*#\s*(\w+)\s*(\w*)", t)
            d = m.group(1) if m else ""
            it["kind"] = "pp-" + d
            if d in ("define", "undef") and m.group(2):
                it["names"] = [m.group(2)]
        elif "{" in t and re.search(r"\)\s*(?:__\w+\s*)*\{", t) and not re.match(r"\s*(typedef\s+)?(struct|union|enum)\b[^()]*\{", t) and "=" not in head.split("(")[0]:
            it["kind"] = "func"
            m = re.search(r"(\w+)\s*\([^()]*(?:\([^()]*\)[^()]*)*\)\s*(?:__\w+\s*)*\{", t, re.S)
            if m:
                it["names"] = [m.group(1)]
        elif re.match(r"\s*(typedef\s+)?(struct|union|enum)\b", t):
            it["kind"] = "type"
            m = re.match(r"\s*(?:typedef\s+)?(?:struct|union|enum)\s+(\w+)", t)
            names = [m.group(1)] if m else []
            m2 = re.search(r"\}\s*(?:__\w+\s*)*(\w+)\s*;\s*$", t)
            if m2:
                names.append(m2.group(1))
            if re.match(r"\s*enum\b", t) and "{" in t:
                body = t[t.find("{") + 1:t.rfind("}")]
                names += re.findall(r"(?:^|,)\s*([A-Za-z_]\w*)", body)
            # a struct type followed by a variable: "struct x name = {...};"
            m3 = re.match(r"\s*(?:static\s+)?(?:const\s+)?(?:struct|union)\s+\w+\s+\**(\w+)\s*(?:\[[^\]]*\])?\s*=", t)
            if m3:
                it["kind"] = "var"
                names = [m3.group(1)]
            it["names"] = names
        elif re.match(r"\s*(module_param\w*|MODULE_PARM_DESC|EXPORT_SYMBOL\w*|late_initcall|module_init|module_exit)\s*\(", t):
            it["kind"] = "macro-call"
            m = re.match(r"\s*(\w+)\s*\(\s*(\w+)", t)
            it["names"] = []
            it["macro"] = m.group(1)
            it["arg"] = m.group(2)
        elif "(" in head and re.search(r"\)\s*;\s*$", t) and not re.search(r"=", head.split("(")[0]):
            it["kind"] = "proto"
            m = re.search(r"(\w+)\s*\([^;]*\)\s*;\s*$", t, re.S)
            it["names"] = [m.group(1)] if m else []
        else:
            it["kind"] = "var"
            decl = head.split("=")[0]
            decl = re.sub(r"\[[^\]]*\]", "", decl)
            m = re.search(r"(\w+)\s*$", decl.strip().rstrip(";"))
            it["names"] = [m.group(1)] if m else []
        body_idents = set(IDENT.findall(t)) - KEYWORDS - set(it["names"])
        it["refs"] = sorted(body_idents)
        it["lines"] = it["end"] - it["start"] + 1
        del it["text"]
        del it["hint"]
    return items


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    items = scan(sys.argv[1])
    if "--summary" in sys.argv:
        for it in items:
            print("%6d-%-6d %5d %-10s %s%s" % (it["start"], it["end"], it["lines"], it["kind"],
                                                "static " if it["static"] else "",
                                                ",".join(it["names"]) or it.get("macro", "")))
    else:
        json.dump(items, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""
Compare every block-scope or file-scope `extern` function declaration in the
module's C sources against the function's definition.

A C compiler checks a call only against the declaration in scope.  A caller
that writes its own `extern` with the wrong parameter list compiles cleanly
and passes garbage for the arguments it left out: 0.89.87's P99-IGET probes
declared mxfs_inode_disk_di_size() with two parameters, and the definition
wrote through the third.  This finds every such disagreement in one pass.

Usage: scripts/extern_decl_audit.py [DIR ...]      (default: xfs pal dlm mxfs_clayer)
Exit status 1 if any declaration disagrees with its definition.
"""
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DIRS = sys.argv[1:] or ["xfs", "pal", "dlm", "mxfs_clayer"]

QUALIFIERS = {"const", "volatile", "struct", "union", "enum", "unsigned",
              "signed", "__user", "__iomem", "restrict", "__restrict"}


def strip_comments(s):
    s = re.sub(r"/\*.*?\*/", lambda m: " " * 0 + "\n" * m.group(0).count("\n"), s, flags=re.S)
    return re.sub(r"//[^\n]*", "", s)


def split_params(p):
    out, depth, cur = [], 0, ""
    for ch in p:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch == "," and depth == 0:
            out.append(cur)
            cur = ""
        else:
            cur += ch
    out.append(cur)
    return [x.strip() for x in out if x.strip()]


def param_type(p):
    """The type of one parameter, with its name (if any) removed."""
    p = re.sub(r"\s+", " ", p).strip()
    p = re.sub(r"\s*\*\s*", " * ", p).strip()
    if "(" in p:                      # function pointer: keep as is, minus name
        return re.sub(r"\(\s*\*\s*\w+\s*\)", "(*)", p).replace(" ", "")
    toks = p.split()
    # drop the trailing identifier when the rest is still a type
    if len(toks) > 1 and re.match(r"^[A-Za-z_]\w*$", toks[-1]) and toks[-1] not in QUALIFIERS \
            and not (len(toks) == 2 and toks[0] in QUALIFIERS - {"const", "volatile"}):
        toks = toks[:-1]
    t = " ".join(toks)
    t = re.sub(r"\[\s*\w*\s*\]", " * ", t)
    return re.sub(r"\s+", "", t)


# Integer spellings that are the same width on every LP64 kernel this builds
# for; a declaration using one and a definition using another agree in the ABI.
WIDTH = {}
for canon, names in {
    "i8": ["s8", "int8_t", "__s8", "signedchar"],
    "u8": ["u8", "uint8_t", "__u8", "unsignedchar"],
    "i16": ["s16", "int16_t", "__s16", "short", "shortint"],
    "u16": ["u16", "uint16_t", "__u16", "unsignedshort", "umode_t"],
    "i32": ["s32", "int32_t", "__s32", "int", "signedint"],
    "u32": ["u32", "uint32_t", "__u32", "unsignedint", "uint", "unsigned"],
    "i64": ["s64", "int64_t", "__s64", "long", "longlong", "longint", "loff_t", "ssize_t"],
    "u64": ["u64", "uint64_t", "__u64", "unsignedlong", "unsignedlonglong", "ulong",
            "sector_t", "size_t", "uintptr_t"],
}.items():
    for n in names:
        WIDTH[n] = canon

TYPEDEFS = {}


def collect_typedefs(src):
    for m in re.finditer(r"\btypedef\s+([^;{}()]+?)\s+\**(\w+)\s*;", src):
        TYPEDEFS.setdefault(m.group(2), re.sub(r"\s+", "", m.group(1)))
    for m in re.finditer(r"\btypedef\s+(struct|union|enum)\s+(\w*)\s*\{", src):
        depth, i = 0, m.end() - 1
        while i < len(src):
            if src[i] == "{":
                depth += 1
            elif src[i] == "}":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        t = re.match(r"\s*(?:__\w+\s*)*(\w+)\s*;", src[i + 1:])  # skip __packed etc.
        if t and m.group(2):
            TYPEDEFS.setdefault(t.group(1), m.group(1) + m.group(2))


def canon(t):
    """Resolve typedefs and same-width integer names in one parameter type."""
    stars = len(t) - len(t.rstrip("*"))
    base = t[:len(t) - stars] if stars else t
    base = base.replace("const", "").replace("volatile", "").replace("__user", "")
    seen = set()
    while base in TYPEDEFS and base not in seen:
        seen.add(base)
        inner = TYPEDEFS[base]
        s2 = len(inner) - len(inner.rstrip("*"))
        stars += s2
        base = inner[:len(inner) - s2] if s2 else inner
        base = base.replace("const", "").replace("volatile", "")
    return WIDTH.get(base, base) + "*" * stars


def sig(params):
    ps = split_params(params)
    if ps == ["void"]:
        ps = []
    return [param_type(p) for p in ps]


def same(a, b):
    return len(a) == len(b) and all(canon(x) == canon(y) for x, y in zip(a, b))


def main():
    defs = {}
    decls = []
    def_re = re.compile(r"(?m)^(?:static\s+)?(?:inline\s+)?[A-Za-z_][\w\s\*]*?[\s\*]"
                        r"(\w+)\s*\(([^;{}]*?)\)\s*\{")
    def_re2 = re.compile(r"(?m)^(\w+)\s*\(([^;{}]*?)\)\s*\{")
    ext_re = re.compile(r"\bextern\s+(?:const\s+)?[A-Za-z_][\w\s\*]*?[\s\*](\w+)\s*\(([^;{}]*?)\)\s*;")
    for d in DIRS:
        for dp, _, fs in os.walk(os.path.join(ROOT, d)):
            for f in fs:
                if not f.endswith((".c", ".h")):
                    continue
                path = os.path.join(dp, f)
                rel = os.path.relpath(path, ROOT)
                src = strip_comments(open(path, errors="replace").read())
                collect_typedefs(src)
                for rx in (def_re, def_re2):
                    for m in rx.finditer(src):
                        name = m.group(1)
                        if name in ("if", "for", "while", "switch", "return", "sizeof"):
                            continue
                        is_static = src[m.start():m.start() + 7] == "static "
                        defs.setdefault(name, []).append((rel, src.count("\n", 0, m.start()) + 1,
                                                          sig(m.group(2)), is_static))
                for m in ext_re.finditer(src):
                    decls.append((rel, src.count("\n", 0, m.start()) + 1, m.group(1), sig(m.group(2))))
    bad = 0
    for rel, line, name, s in decls:
        cands = [x for x in defs.get(name, []) if not x[3]]
        if not cands:
            continue
        if any(same(c[2], s) for c in cands):
            continue
        c = cands[0]
        how = "arity %d vs %d" % (len(s), len(c[2])) if len(s) != len(c[2]) else "types differ"
        print("%s:%d: extern %s(%s) — definition %s:%d takes (%s) [%s]"
              % (rel, line, name, ", ".join(s), c[0], c[1], ", ".join(c[2]), how))
        bad += 1
    print("%d extern declarations checked, %d disagree with their definition"
          % (len(decls), bad), file=sys.stderr)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())

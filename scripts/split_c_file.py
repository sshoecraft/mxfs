#!/usr/bin/env python3
"""
Split one large C file into several translation units that share a private
header, without changing what any function does.

    scripts/split_c_file.py PLAN.json            write the files
    scripts/split_c_file.py PLAN.json --report   print the assignment only

PLAN.json:
    {
      "source":  "xfs/xfs_mxfs_dlm.c",
      "header":  "xfs/xfs_mxfs_dlm_priv.h",
      "guard":   "__XFS_MXFS_DLM_PRIV_H__",
      "header_comment": "...",          # text of the header's top comment
      "keep_top_lines": 16,             # source lines 1..N stay atop files[0]
      "files": [
        {"path": "xfs/xfs_mxfs_dlm.c", "id": 1, "title": "...",
         "ranges": [[176, 1224], ...]},  # function first-code-lines to take
        ...
      ]
    }

Every function must fall in exactly one range.  Everything else is placed
automatically:

  * #include, #define, struct/union/enum definitions, forward declarations
    and extern declarations go to the header, in source order;
  * a variable (or DEFINE_SPINLOCK and kin) goes to the file whose functions
    reference it most, or beside the function that precedes it when no
    function does;
  * module_param*, MODULE_PARM_DESC and EXPORT_SYMBOL follow what they name;
  * a function or variable referenced from another file loses `static` and
    is declared once in the header (a reference through a header macro
    counts, transitively);
  * a static function used above its definition in its new file gets a
    forward prototype at the top of that file.

`#define igrab/iput` wrappers that carry a per-file call-site id take the
file's "id" through MXFS_TU_ID, which each generated file defines before
including the header.
"""
import importlib.util
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
spec = importlib.util.spec_from_file_location("cmap", os.path.join(HERE, "c_toplevel_map.py"))
cmap = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cmap)

IDENT = re.compile(r"[A-Za-z_]\w*")
MVAR_EXTERN = {
    "DEFINE_SPINLOCK": lambda a: "extern spinlock_t %s;" % a[0],
    "DEFINE_MUTEX": lambda a: "extern struct mutex %s;" % a[0],
    "DEFINE_HASHTABLE": lambda a: "extern struct hlist_head %s[1 << (%s)];" % (a[0], a[1]),
    "DEFINE_STATIC_KEY_FALSE": lambda a: "DECLARE_STATIC_KEY_FALSE(%s);" % a[0],
    "DEFINE_STATIC_KEY_TRUE": lambda a: "DECLARE_STATIC_KEY_TRUE(%s);" % a[0],
    "LIST_HEAD": lambda a: "extern struct list_head %s;" % a[0],
    "DECLARE_WAIT_QUEUE_HEAD": lambda a: "extern wait_queue_head_t %s;" % a[0],
}


def die(msg):
    sys.stderr.write("split_c_file: %s\n" % msg)
    sys.exit(1)


def split_top(s, sep=","):
    out, depth, cur = [], 0, ""
    for ch in s:
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        if ch == sep and depth == 0:
            out.append(cur)
            cur = ""
        else:
            cur += ch
    out.append(cur)
    return [x.strip() for x in out]


def one_line(s):
    return re.sub(r"\s+", " ", s).strip()


def parse_var(clean):
    """[(name, extern declaration)] for a variable definition statement."""
    t = one_line(clean).rstrip(";").strip()
    t = re.sub(r"^static\s+", "", t)
    parts = split_top(t)
    out = []
    base = None
    for i, p in enumerate(parts):
        decl = split_top(p, "=")[0].strip()
        m = re.search(r"\(\s*\*\s*(\w+)\s*\)", decl)
        if m:
            name = m.group(1)
        else:
            d2 = re.sub(r"\[[^\]]*\]", "", decl)
            d2 = re.sub(r"(\s+__\w+(\([^)]*\))?)+$", "", d2).strip()
            m = re.search(r"(\w+)\s*$", d2)
            if not m:
                die("cannot name a declarator in: %s" % t[:120])
            name = m.group(1)
        if i == 0:
            idx = decl.rfind(name) if not re.search(r"\(\s*\*", decl) else decl.find("(")
            head = decl[:idx]
            stars = len(head) - len(head.rstrip(" *"))
            base = head.rstrip(" *").strip()
            declarator = decl[len(base):].strip()
        else:
            declarator = decl
        out.append((name, "extern %s %s;" % (base, declarator)))
    return out


def func_proto(clean_code):
    head = clean_code[:clean_code.find("{")]
    head = one_line(head)
    head = re.sub(r"^(static\s+)?(inline\s+)?", "", head)
    head = re.sub(r"^(inline\s+)", "", head)
    return head + ";"


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    plan = json.load(open(sys.argv[1]))
    report_only = "--report" in sys.argv
    src_path = os.path.join(ROOT, plan["source"])
    raw = open(src_path).read()
    rawl = raw.split("\n")
    clean = cmap.blank_comments_and_strings(raw)
    cleanl = clean.split("\n")
    items = cmap.scan(src_path)

    def rtext(it):
        return "\n".join(rawl[it["start"] - 1:it["end"]])

    def ctext(it):
        return "\n".join(cleanl[it["code_start"] - 1:it["end"]])

    files = plan["files"]
    fidx = {f["path"]: i for i, f in enumerate(files)}

    # ---- classify
    func_names = set()
    for it in items:
        c = ctext(it)
        first = one_line(c)
        it["role"] = None
        if it["kind"] == "func":
            it["role"] = "func"
            func_names.update(it["names"])
            continue
        if it["kind"].startswith("pp-"):
            it["role"] = "hdr"
            continue
        m = re.match(r"(static\s+)?(DEFINE_\w+|LIST_HEAD|DECLARE_WAIT_QUEUE_HEAD)\s*\(([^)]*)\)\s*;?$", first)
        if m and m.group(2) == "DEFINE_SHOW_ATTRIBUTE":
            a = m.group(3).strip()
            it["role"] = "showattr"
            it["names"] = [a + "_open", a + "_fops"]
            it["refs"] = sorted(set(it["refs"]) | {a + "_show"})
            continue
        if m:
            args = [x.strip() for x in split_top(m.group(3))]
            if m.group(2) not in MVAR_EXTERN:
                die("no extern form for %s at line %d" % (m.group(2), it["code_start"]))
            it["role"] = "var"
            it["names"] = [args[0]]
            it["decls"] = [(args[0], MVAR_EXTERN[m.group(2)](args))]
            it["static"] = bool(m.group(1))
            continue
        if re.match(r"extern\b", first):
            it["role"] = "hdr"
            continue
        if re.match(r"(struct|union|enum)\s+\w+\s*;$", first):
            it["role"] = "hdr"
            continue
        if re.match(r"(typedef\s+)?(struct|union|enum)\b[^=(]*\{", first) and not re.search(r"\}\s*\**\s*\w+\s*(\[[^\]]*\])?\s*(=.*)?;$", first.replace("} __packed", "}")) or re.match(r"typedef\b", first):
            it["role"] = "hdr"
            continue
        if it["kind"] == "macro-call":
            it["role"] = "mcall"
            continue
        # function declaration (possibly static, possibly with attributes)
        if re.match(r"(static\s+)?(inline\s+)?[\w\s\*]+?\b(\w+)\s*\([^;{}]*\)\s*(__\w+(\([^)]*\))?\s*)*;$", first) and "=" not in first.split("(")[0]:
            name = re.match(r"(static\s+)?(inline\s+)?[\w\s\*]+?\b(\w+)\s*\(", first).group(3)
            it["role"] = "fproto"
            it["names"] = [name]
            continue
        it["role"] = "var"
        it["decls"] = parse_var(c)
        it["names"] = [d[0] for d in it["decls"]]
        it["static"] = bool(re.match(r"static\b", first))

    for it in items:
        if it["role"] == "fproto" and not (set(it["names"]) & func_names):
            it["role"] = "hdr"      # declares something defined elsewhere

    # ---- macro expansion of references (header macros)
    macro_refs = {}
    for it in items:
        if it["kind"] == "pp-define" and it["names"]:
            macro_refs[it["names"][0]] = set(it["refs"])
    changed = True
    while changed:
        changed = False
        for k, v in macro_refs.items():
            add = set()
            for r in v:
                if r in macro_refs and r != k:
                    add |= macro_refs[r]
            if not add <= v:
                v |= add
                changed = True

    def full_refs(it):
        refs = set(it["refs"])
        for r in list(refs):
            if r in macro_refs:
                refs |= macro_refs[r]
        return refs

    for it in items:
        it["frefs"] = full_refs(it)

    # ---- assign functions
    for it in items:
        if it["role"] != "func":
            continue
        cs = it["code_start"]
        hits = [f["path"] for f in files for a, b in f["ranges"] if a <= cs <= b]
        if len(hits) != 1:
            die("function %s at line %d falls in %d plan ranges" % (it["names"], cs, len(hits)))
        it["file"] = hits[0]

    owner = {}
    for it in items:
        if it["role"] == "func":
            for n in it["names"]:
                owner[n] = it

    # ---- assign variables
    last_func_file = None
    order_file = []
    for it in items:
        if it["role"] == "func":
            last_func_file = it["file"]
        order_file.append(last_func_file or files[0]["path"])
    by_name_vars = {}
    for idx, it in enumerate(items):
        if it["role"] in ("var", "showattr"):
            votes = {}
            for u in items:
                if u["role"] == "func" and set(it["names"]) & u["frefs"]:
                    votes[u["file"]] = votes.get(u["file"], 0) + 1
            if it["role"] == "showattr" and not votes:
                # the macro's fops are static: they live where they are
                # registered, and the _show function is what gets shared
                show = it["names"][0][:-len("_open")] + "_show"
                it["file"] = owner[show]["file"] if show in owner else order_file[idx]
            elif votes:
                best = max(votes.values())
                it["file"] = min((fidx[f], f) for f, v in votes.items() if v == best)[1]
            else:
                it["file"] = order_file[idx]
            for n in it["names"]:
                by_name_vars.setdefault(n, []).append(it)
    # tentative definitions and the definition of one name stay together
    for n, its in by_name_vars.items():
        if len(its) > 1:
            f = its[-1]["file"]
            for it in its:
                it["file"] = f
    for it in items:
        if it["role"] in ("var", "showattr"):
            for n in it["names"]:
                owner[n] = it

    # ---- macro calls
    param_file = {}
    for idx, it in enumerate(items):
        if it["role"] != "mcall":
            continue
        c = one_line(ctext(it))
        m = re.match(r"(\w+)\s*\((.*)\)\s*;?$", c)
        mac, args = m.group(1), split_top(m.group(2))
        target = None
        if mac == "module_param_named":
            target = args[1].lstrip("&")
            param_file[args[0]] = None
        elif mac == "module_param":
            target = args[0]
        elif mac in ("module_param_cb", "module_param_call"):
            target = args[1].lstrip("&")
        elif mac.startswith("EXPORT_SYMBOL"):
            target = args[0]
        elif mac == "MODULE_PARM_DESC":
            target = None
        f = owner[target]["file"] if target in owner else order_file[idx]
        it["file"] = f
        if mac.startswith("module_param"):
            param_file[args[0]] = f
        it["mac"], it["args"] = mac, args
    for idx, it in enumerate(items):
        if it["role"] == "mcall" and it["mac"] == "MODULE_PARM_DESC":
            it["file"] = param_file.get(it["args"][0]) or order_file[idx]

    # ---- sharing
    shared = set()
    for it in items:
        if it["role"] in ("func", "var", "showattr", "mcall"):
            for r in it["frefs"]:
                o = owner.get(r)
                if o is not None and o is not it and o["file"] != it["file"]:
                    shared.add(r)
    for it in items:
        if it["role"] == "showattr" and set(it["names"]) & shared:
            die("DEFINE_SHOW_ATTRIBUTE %s is used from another file" % it["names"])

    # ---- forward prototypes for statics used above their definition
    fwd = {f["path"]: [] for f in files}
    pos = {id(it): i for i, it in enumerate(items)}
    for it in items:
        if it["role"] != "func" or not re.match(r"static\b", one_line(ctext(it))):
            continue
        n = it["names"][0]
        if n in shared:
            continue
        for u in items[:pos[id(it)]]:
            if u.get("file") == it["file"] and n in u["frefs"] and u["role"] != "fproto":
                fwd[it["file"]].append("static " + func_proto(ctext(it)))
                break

    # ---- report
    sizes = {f["path"]: 0 for f in files}
    for it in items:
        if it.get("file"):
            sizes[it["file"]] += it["end"] - it["start"] + 1
    hdr_lines = sum(it["end"] - it["start"] + 1 for it in items if it["role"] in ("hdr", "fproto"))
    if report_only:
        for f in files:
            print("%-36s %6d lines" % (f["path"], sizes[f["path"]]))
        print("%-36s %6d lines (+%d generated declarations)" % (plan["header"], hdr_lines, len(shared)))
        print("shared symbols: %d" % len(shared))
        return 0

    # ---- emit header
    H = []
    H.append("/* SPDX-License-Identifier: GPL-2.0 */")
    H.append("/*")
    for l in plan["header_comment"].split("\n"):
        H.append((" * " + l).rstrip())
    H.append(" */")
    H.append("#ifndef %s" % plan["guard"])
    H.append("#define %s" % plan["guard"])
    H.append("")
    keep = plan.get("keep_top_lines", 0)
    for it in items:
        if it["role"] != "hdr":
            continue
        t = rtext(it)
        if it["start"] <= keep:
            t = "\n".join(rawl[keep:it["end"]])
        t = re.sub(r"(#define (?:igrab|iput)\(vi\) mxfs_\w+_tracked\(\(vi\), __LINE__, )\d+\)", r"\1MXFS_TU_ID)", t)
        H.append(t)
    H.append("")
    H.append("/* Defined in one of the files above and used from another. */")
    decl_done = set()
    for it in items:
        if it["role"] == "var" and set(it["names"]) & shared:
            for n, d in it["decls"]:
                if n in shared and n not in decl_done:
                    H.append(d)
                    decl_done.add(n)
    for it in items:
        if it["role"] == "func" and it["names"][0] in shared:
            H.append(func_proto(ctext(it)))
    H.append("")
    H.append("#endif /* %s */" % plan["guard"])
    out = {plan["header"]: "\n".join(H) + "\n"}

    # ---- emit files
    for f in files:
        L = []
        if f is files[0] and keep:
            L.extend(rawl[:keep])
        else:
            L.append("// SPDX-License-Identifier: GPL-2.0")
            L.append("/*")
            for l in f["title"].split("\n"):
                L.append((" * " + l).rstrip())
            L.append(" */")
        L.append("#define MXFS_TU_ID %d\t/* igrab/iput call-site file id */" % f["id"])
        L.append('#include "%s"' % os.path.basename(plan["header"]))
        if fwd[f["path"]]:
            L.append("")
            L.extend(fwd[f["path"]])
        for it in items:
            if it.get("file") != f["path"] or it["role"] in ("hdr", "fproto"):
                continue
            t = rtext(it)
            if it["role"] in ("func", "var") and set(it["names"]) & shared:
                cs = it["code_start"] - it["start"]
                lines = t.split("\n")
                code = "\n".join(lines[cs:])
                code2 = re.sub(r"^static\s+(inline\s+)?", "", code, count=1)
                if code2 == code and re.match(r"static\b", one_line(ctext(it))):
                    die("could not drop static from %s" % it["names"])
                t = "\n".join(lines[:cs] + [code2])
            L.append(t)
        out[f["path"]] = "\n".join(L).rstrip("\n") + "\n"

    for p, text in out.items():
        with open(os.path.join(ROOT, p), "w") as fh:
            fh.write(text)
    for f in files:
        print("%-36s %6d lines" % (f["path"], out[f["path"]].count("\n")))
    print("%-36s %6d lines" % (plan["header"], out[plan["header"]].count("\n")))
    print("shared symbols: %d" % len(shared))
    return 0


if __name__ == "__main__":
    sys.exit(main())

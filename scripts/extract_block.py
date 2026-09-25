#!/usr/bin/env python3
"""
Move one statement block out of a C function into a static helper, without
changing what the code does, or refuse.

MXFS's largest functions run to thousands of lines.  This takes one
statement (a braced block, an if, a loop or a switch) that is a direct child
of a compound statement inside FUNCTION, and turns it into

    static <int|void> NAME(<captured variables>)
    {
        <locals the block modifies, copied in>
        <the block, text unchanged except return/goto>
    NAME_exit:
        <those locals copied back out>
    }

placed immediately before FUNCTION, with a call at the block's old place.
It works from clang's AST of the real kernel build, not from text:

  - A local of FUNCTION the block only reads is passed by value under its
    own name.  One it modifies (assignment, ++/--, a member store) is passed
    by pointer and copied in at entry and back out at every exit, so the
    block's text -- and any macro that touches the local -- is unchanged.
    Arrays are passed as a pointer to their first element and never copied.
  - A `return` in the block becomes "store the value, leave with RETURN";
    a `goto` to a label outside it becomes "leave with GOTO+k"; the call site
    returns or jumps accordingly.

It refuses, and changes nothing, when the move could change meaning:

  - a captured local whose address is taken anywhere in FUNCTION (a copy
    would split one object into two), or a function-local static;
  - `break`, `continue`, `case` or `default` whose loop or switch is outside
    the block, or a label inside it that a goto outside it targets;
  - a `return` or `goto` spelled inside a macro, where it cannot be rewritten;
  - `sizeof`/`ARRAY_SIZE` of a captured array (it would measure a pointer);
  - `__func__`, `_RET_IP_` or `__builtin_return_address`;
  - a type, typedef or #define declared inside FUNCTION, or the block sitting
    inside (or containing an unbalanced) #if region of FUNCTION.

Needs the Python bindings for the installed libclang
(`pip install clang==18.1.8` into a venv; libclang-18 from llvm-18), and the
module built once so the kernel's compile flags can be read from the
object's .cmd file.

Usage:
    extract_block.py FILE FUNCTION --list [--min 40]
    extract_block.py FILE FUNCTION LINE NAME [--doc TEXT] [--apply]
        LINE: the line the statement starts on; NAME: the helper's name.
        The comment above the block becomes the helper's; a block with none
        needs --doc.
    --cflags "FLAGS" parses FILE with FLAGS instead of the kernel build's own
    (tests/extract_block_selftest.sh uses it on a plain user-space file).
"""
import ctypes
import os
import re
import shlex
import sys

try:
    import clang.cindex as ci
except ImportError:
    sys.exit("extract_block: needs the libclang Python bindings "
             "(python3 -m venv V; V/bin/pip install clang==18.1.8; run with V/bin/python)")

LIBCLANG = os.environ.get("LIBCLANG", "/usr/lib/llvm-18/lib/libclang-18.so.1")
ci.Config.set_library_file(LIBCLANG)
ci.conf.lib.clang_getSpellingLocation.argtypes = [
    ci.SourceLocation, ctypes.POINTER(ci.c_object_p), ctypes.POINTER(ctypes.c_uint),
    ctypes.POINTER(ctypes.c_uint), ctypes.POINTER(ctypes.c_uint)]
ci.conf.lib.clang_getSpellingLocation.restype = None


def spelling_location(loc):
    """(file handle or None, file identity, byte offset) where loc is written."""
    f = ci.c_object_p()
    ln, col, off = ctypes.c_uint(), ctypes.c_uint(), ctypes.c_uint()
    ci.conf.lib.clang_getSpellingLocation(loc, ctypes.byref(f), ctypes.byref(ln),
                                          ctypes.byref(col), ctypes.byref(off))
    ident = ctypes.cast(f, ctypes.c_void_p).value
    return (f if ident else None), ident, off.value
K = ci.CursorKind
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOOPS = (K.FOR_STMT, K.WHILE_STMT, K.DO_STMT)
MOVABLE = (K.COMPOUND_STMT, K.IF_STMT, K.FOR_STMT, K.WHILE_STMT, K.DO_STMT, K.SWITCH_STMT)
ASSIGN_OPS = {"=", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "<<=", ">>="}
# _THIS_IP_ / __this_address stay allowed: they only report a code address in
# a corruption message, and a helper's address points at the same code
FORBIDDEN_IDS = {"__func__", "__FUNCTION__", "_RET_IP_", "__builtin_return_address"}


class Refuse(Exception):
    pass


def kernel_args(path):
    """-I/-D/-include flags of the file's own compile, and the kernel dir."""
    d, b = os.path.split(os.path.abspath(path))
    cmdf = os.path.join(d, "." + b[:-2] + ".o.cmd")
    if not os.path.exists(cmdf):
        sys.exit("extract_block: %s missing; build the module first" % cmdf)
    cmd = open(cmdf).readline().split(":=", 1)[1]
    toks = shlex.split(cmd)
    keep, i = [], 0
    while i < len(toks):
        t = toks[i]
        if t in ("-include", "-isystem", "-I", "-D"):
            keep += [t, toks[i + 1]]
            i += 2
            continue
        if t.startswith(("-I", "-D", "-std=", "-nostdinc", "-isystem")):
            keep.append(t)
        i += 1
    kdir = os.path.realpath("/lib/modules/%s/build" % os.uname().release)
    return keep + ["-ferror-limit=0", "-Wno-everything"], kdir


CFLAGS = None       # --cflags: parse a plain file with these flags instead


def parse(path):
    if CFLAGS is not None:
        args, kdir = shlex.split(CFLAGS) + ["-ferror-limit=0", "-Wno-everything"], os.getcwd()
    else:
        args, kdir = kernel_args(path)
    here = os.getcwd()
    os.chdir(kdir)
    try:
        tu = ci.Index.create().parse(os.path.abspath(os.path.join(here, path)), args=args,
                                     options=ci.TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD)
    finally:
        os.chdir(here)
    errs = [d for d in tu.diagnostics if d.severity >= 3]
    if errs:
        sys.exit("extract_block: clang could not parse %s: %s" % (path, errs[0].spelling))
    return tu


def find_function(tu, path, name):
    ap = os.path.abspath(path)
    for c in tu.cursor.get_children():
        if c.kind == K.FUNCTION_DECL and c.spelling == name and c.is_definition() \
                and c.location.file and os.path.abspath(c.location.file.name) == ap:
            return c
    sys.exit("extract_block: no definition of %s in %s" % (name, path))


def walk(cur, anc, out):
    """Every descendant with its ancestor chain (outermost first)."""
    out.append((cur, anc))
    na = anc + [cur]
    for ch in cur.get_children():
        walk(ch, na, out)


def inside(c, lo, hi):
    return lo <= c.extent.start.offset and c.extent.end.offset <= hi


class Func:
    def __init__(self, tu, path, fname):
        self.path = path
        # latin-1 maps each byte to one character, so string indices are
        # the byte offsets clang reports (the sources hold UTF-8 dashes and
        # arrows); written back the same way, every byte round-trips
        self.src = open(path, encoding="latin-1").read()
        self.fn = find_function(tu, path, fname)
        sys.setrecursionlimit(20000)
        self.nodes = []
        walk(self.fn, [], self.nodes)
        self.lo, self.hi = self.fn.extent.start.offset, self.fn.extent.end.offset
        self.locals = {}                # decl hash -> decl cursor
        for c, _ in self.nodes:
            if c.kind in (K.VAR_DECL, K.PARM_DECL) and inside(c, self.lo, self.hi):
                self.locals[c.hash] = c
        self.tokens = {t.spelling for t in self.fn.get_tokens()}
        self.file_ptr = spelling_location(self.fn.extent.start)[1]
        self.files = {}
        ap = os.path.abspath(path)
        self.macros = sorted((m.extent.start.offset, m.extent.end.offset)
                             for m in tu.cursor.get_children()
                             if m.kind == K.MACRO_INSTANTIATION and m.location.file
                             and os.path.abspath(m.location.file.name) == ap
                             and self.lo <= m.extent.start.offset < self.hi)

    def in_macro(self, off):
        """True when offset off lies inside a macro invocation's text."""
        for a, b in self.macros:
            if a <= off < b:
                return True
            if a > off:
                return False
        return False

    def text(self, a, b):
        return self.src[a:b]

    def line_of(self, off):
        return self.src.count("\n", 0, off) + 1

    def spelling(self, c):
        """Byte offset in this file where c's first token is written, or
        None.  A token from a macro argument is written at the argument; one
        from a macro body is written in the #define, outside the function."""
        f, ident, off = spelling_location(c.extent.start)
        if ident != self.file_ptr or not (self.lo <= off < self.hi):
            return None
        return off

    def spell(self, loc):
        """(file name, byte offset) where a location is written."""
        f, ident, off = spelling_location(loc)
        if f is None:
            return None, None
        return ci.conf.lib.clang_getFileName(ci.File(f)), off

    def spelled_between(self, a, b):
        """Source text written between two locations in one file, or None."""
        fa, oa = self.spell(a)
        fb, ob = self.spell(b)
        if fa is None or fa != fb or ob < oa or ob - oa > 64:
            return None
        if fa not in self.files:
            self.files[fa] = open(fa, encoding="latin-1").read()
        return self.files[fa][oa:ob]

    def writes(self, ref, anc, array):
        """Whether this use of a variable may store to it, decided from the
        AST and the operators' own text wherever they are written (inside a
        macro argument or a macro's #define).  Unreadable means yes."""
        node = ref
        for x in reversed(anc):
            kids = list(x.get_children())
            if x.kind == K.PAREN_EXPR:
                node = x
                continue
            if x.kind == K.UNEXPOSED_EXPR and len(kids) == 1 and \
                    x.type.get_canonical() == kids[0].type.get_canonical():
                node = x                    # an implicit cast that keeps the type
                continue
            if x.kind == K.MEMBER_REF_EXPR and kids and kids[0].type.kind != ci.TypeKind.POINTER:
                node = x                    # v.f -- a store to it is a store to v
                continue
            if x.kind == K.ARRAY_SUBSCRIPT_EXPR and array and kids and kids[0].hash == node.hash:
                node = x
                continue
            parent = x
            break
        else:
            return False
        kids = list(parent.get_children())
        if parent.kind == K.COMPOUND_ASSIGNMENT_OPERATOR:
            return bool(kids) and kids[0].hash == node.hash
        if parent.kind == K.BINARY_OPERATOR:
            if not kids or kids[0].hash != node.hash or len(kids) < 2:
                return False
            op = self.spelled_between(kids[0].extent.end, kids[1].extent.start)
            return op is None or op.strip().strip("()").strip() == "="
        if parent.kind == K.UNARY_OPERATOR:
            pre = self.spelled_between(parent.extent.start, node.extent.start)
            post = self.spelled_between(node.extent.end, parent.extent.end)
            if pre is None or post is None:
                return True
            return "++" in pre + post or "--" in pre + post
        return False

    def spelled_here(self, c, word):
        """True when c's first token is `word`, written in this function's
        own text (a macro argument counts; a macro body does not)."""
        o = self.spelling(c)
        return o is not None and self.src.startswith(word, o) and \
            not re.match(r"\w", self.src[o + len(word):o + len(word) + 1] or " ")

    def statements(self, minlines):
        """Movable statements that are direct children of a compound statement."""
        out = []
        for c, anc in self.nodes:
            if c.kind in MOVABLE and anc and anc[-1].kind == K.COMPOUND_STMT and anc[-1] != self.fn:
                n = self.line_of(c.extent.end.offset) - self.line_of(c.extent.start.offset) + 1
                if n >= minlines:
                    out.append((c, anc, n))
        return out


def token_after(src, off):
    m = re.compile(r"\s*(->|\+\+|--|<<=|>>=|[-+*/%&|^]=|==|!=|=|\.|\[)").match(src, off)
    return m.group(1) if m else ""


def token_before(src, off):
    m = re.search(r"(\+\+|--|&&|&|\*|!|-|~)\s*$", src[max(0, off - 8):off])
    return m.group(1) if m else ""


def lvalue(src, ref, anc, array):
    """Climb from a variable reference through (v), v.f and v[i] (an array's
    element); return the lvalue's span and the node that uses it."""
    e_lo, e_hi = ref.extent.start.offset, ref.extent.end.offset
    for x in reversed(anc):
        if x.kind == K.PAREN_EXPR:
            pass
        elif x.kind == K.UNEXPOSED_EXPR and x.extent.start.offset == e_lo and \
                x.extent.end.offset == e_hi:
            pass                        # an implicit cast of exactly this text
        elif x.kind == K.MEMBER_REF_EXPR and token_after(src, e_hi) == ".":
            pass
        elif x.kind == K.ARRAY_SUBSCRIPT_EXPR and array and x.extent.start.offset == e_lo:
            pass
        else:
            return e_lo, e_hi, x
        e_lo, e_hi = x.extent.start.offset, x.extent.end.offset
    return e_lo, e_hi, None


def analyse(F, stmt, anc):
    lo, hi = stmt.extent.start.offset, stmt.extent.end.offset
    src = F.src
    body = F.text(lo, hi)

    # preprocessor: the block must not sit in, or cut across, an #if region
    # of the function, and the function must #define nothing
    fbody = F.text(F.lo, F.hi)
    depth, at_start, start_seen = 0, None, False
    pos = F.lo
    for line in fbody.split("\n"):
        s = line.strip()
        if pos >= lo and not start_seen:
            at_start, start_seen = depth, True
        if re.match(r"#\s*(if|ifdef|ifndef)\b", s):
            depth += 1
        elif re.match(r"#\s*endif\b", s):
            depth -= 1
        elif re.match(r"#\s*(define|undef)\b", s):
            raise Refuse("the function #defines or #undefs a macro")
        pos += len(line) + 1
    if at_start:
        raise Refuse("the block sits inside an #if region of the function")
    d = 0
    for line in body.split("\n"):
        s = line.strip()
        if re.match(r"#\s*(if|ifdef|ifndef)\b", s):
            d += 1
        elif re.match(r"#\s*endif\b", s):
            d -= 1
        elif re.match(r"#\s*(else|elif)\b", s) and d == 0:
            raise Refuse("an #else/#elif in the block belongs to an #if outside it")
        if d < 0:
            raise Refuse("an #endif in the block closes an #if outside it")
    if d:
        raise Refuse("an #if in the block is closed outside it")

    for w in FORBIDDEN_IDS:
        if re.search(r"\b%s\b" % re.escape(w), body):
            raise Refuse("the block uses %s, which would name the helper" % w)

    captured = {}           # hash -> {decl, io, array}
    order = []
    returns, gotos = [], []
    labels_in = {}
    for c, a in F.nodes:
        if c.kind == K.LABEL_STMT and inside(c, lo, hi):
            labels_in[c.spelling] = c
    for c, a in F.nodes:
        inb = inside(c, lo, hi)
        k = c.kind
        if k == K.GOTO_STMT:
            tgt = [x for x in c.get_children() if x.kind == K.LABEL_REF]
            name = tgt[0].spelling if tgt else None
            if inb and name not in labels_in:
                if not F.spelled_here(c, "goto"):
                    raise Refuse("a goto out of the block is spelled inside a macro")
                gotos.append((c, name))
            if not inb and name in labels_in:
                raise Refuse("a goto outside the block targets label %s inside it" % name)
        if not inb:
            continue
        if k == K.RETURN_STMT:
            if not F.spelled_here(c, "return"):
                raise Refuse("a return in the block is spelled inside a macro")
            returns.append(c)
        elif k in (K.BREAK_STMT, K.CONTINUE_STMT):
            tgt = None
            for x in reversed(a):
                if x.kind in LOOPS or (k == K.BREAK_STMT and x.kind == K.SWITCH_STMT):
                    tgt = x
                    break
            if tgt is None or not inside(tgt, lo, hi):
                raise Refuse("%s at line %d leaves the block" %
                             ("break" if k == K.BREAK_STMT else "continue",
                              F.line_of(c.extent.start.offset)))
        elif k in (K.CASE_STMT, K.DEFAULT_STMT):
            sw = next((x for x in reversed(a) if x.kind == K.SWITCH_STMT), None)
            if sw is None or not inside(sw, lo, hi):
                raise Refuse("a case label in the block belongs to a switch outside it")
        elif k == K.ADDR_LABEL_EXPR:
            raise Refuse("the block takes a label's address")
        elif k == K.TYPE_REF:
            dcl = c.referenced
            if dcl is not None and dcl.location.file and \
                    os.path.abspath(dcl.location.file.name) == os.path.abspath(F.path) and \
                    F.lo <= dcl.extent.start.offset < F.hi and not inside(dcl, lo, hi):
                raise Refuse("the block uses type %s declared inside the function" % c.spelling)
        elif k == K.DECL_REF_EXPR:
            dcl = c.referenced
            if dcl is None or dcl.hash not in F.locals or inside(dcl, lo, hi):
                continue
            h = dcl.hash
            if h not in captured:
                t = dcl.type
                captured[h] = {"decl": dcl, "io": False, "addr": False, "refs": [],
                               "implicit": False,
                               "static": dcl.storage_class == ci.StorageClass.STATIC,
                               "array": t.kind in (ci.TypeKind.CONSTANTARRAY,
                                                   ci.TypeKind.INCOMPLETEARRAY)}
                order.append(h)
            cap = captured[h]
            if cap["array"] and re.search(r"\b(sizeof|ARRAY_SIZE)\s*\(?\s*%s\b" % re.escape(dcl.spelling), body):
                raise Refuse("the block takes sizeof of captured array %s" % dcl.spelling)
            if F.spelled_here(c, dcl.spelling):
                o = F.spelling(c)
                # a macro that uses its argument twice yields two references
                # written at the same place: one rewrite, not two
                if (o, o + len(dcl.spelling)) not in cap["refs"]:
                    cap["refs"].append((o, o + len(dcl.spelling)))
            else:
                cap["implicit"] = True  # named inside a macro body, not in the text
            if cap["io"]:
                continue
            # Passing by value is the exception and must be proven: any use
            # whose operator cannot be read is taken as a write.
            if not F.spelled_here(c, dcl.spelling) or F.in_macro(c.extent.start.offset):
                if F.writes(c, a, cap["array"]):
                    cap["io"] = True
                continue
            e_lo, e_hi, parent = lvalue(src, c, a, cap["array"])
            nxt, prv = token_after(src, e_hi), token_before(src, e_lo)
            if nxt in ASSIGN_OPS or nxt in ("++", "--") or prv in ("++", "--"):
                cap["io"] = True

    # A captured local whose address is taken anywhere in the function cannot
    # be copied -- the copy and the original would be two objects -- so it is
    # passed by reference.  Found by type, so an & written inside a macro
    # body (READ_ONCE's &(x), say) counts too.
    for c, a in F.nodes:
        if c.kind != K.DECL_REF_EXPR:
            continue
        dcl = c.referenced
        if dcl is None or dcl.hash not in captured or captured[dcl.hash]["array"]:
            continue
        e_lo, e_hi, parent = lvalue(src, c, a, False)
        if parent is not None and parent.kind == K.UNARY_OPERATOR and \
                parent.type.kind == ci.TypeKind.POINTER:
            operand = next(iter(parent.get_children()), None)
            if operand is not None and parent.type.get_pointee().get_canonical() == \
                    operand.type.get_canonical():
                captured[dcl.hash]["addr"] = True

    # How each captured local travels:
    #   array            pointer to its first element, text unchanged
    #   static or addr   by reference: &v passed, each mention rewritten (*v_ref)
    #   written          copied in at entry and out at every exit, text unchanged
    #   otherwise        by value under its own name
    for cap in captured.values():
        if cap["array"]:
            cap["mode"] = "array"
        elif cap["static"] or cap["addr"]:
            if cap["implicit"]:
                raise Refuse("%s must be passed by reference but a macro body names it" %
                             cap["decl"].spelling)
            cap["mode"] = "ref"
        elif cap["io"]:
            cap["mode"] = "copy"
        else:
            cap["mode"] = "value"

    return {"lo": lo, "hi": hi, "captured": [captured[h] for h in order],
            "returns": returns, "gotos": gotos}


def declarator(tspell, name):
    """C declaration of `name` with type spelling tspell."""
    if "(*)" in tspell:
        return tspell.replace("(*)", "(*%s)" % name, 1)
    if "unnamed" in tspell or "anonymous" in tspell:
        raise Refuse("a captured variable has an unnamed type")
    return "%s%s%s" % (tspell, "" if tspell.endswith("*") else " ", name)


def ptr_declarator(tspell, name):
    """C declaration of `name` as a pointer to type tspell."""
    if "(*)" in tspell:
        return tspell.replace("(*)", "(**%s)" % name, 1)
    return declarator(tspell + ("*" if tspell.endswith("*") else " *"), name)


def param_type(cap):
    t = cap["decl"].type
    if cap["array"]:
        return t.element_type.spelling + " *"
    return t.spelling


def leading_comment(F, lo):
    """The comment block directly above offset lo, with its span."""
    line_start = F.src.rfind("\n", 0, lo) + 1
    prev_end = line_start - 1
    if prev_end <= 0:
        return None
    before = F.src[:prev_end]
    m = re.search(r"(/\*(?:(?!/\*).)*?\*/)[ \t]*$", before, re.S)
    if not m:
        return None
    s = F.src.rfind("\n", 0, m.start(1)) + 1
    if F.src[s:m.start(1)].strip():
        return None                     # the comment trails code on its line
    return s, prev_end + 1


def wrap_list(head, items, tail, indent, width=80):
    """head(item, item, ...)tail, wrapped kernel style: continuation lines
    aligned after the opening parenthesis (tabs, then spaces)."""
    one = indent + head + ", ".join(items) + tail
    if len(one.expandtabs(8)) <= width or not items:
        return one
    col = len((indent + head).expandtabs(8))
    cont = "\t" * (col // 8) + " " * (col % 8)
    lines, cur = [], indent + head + items[0]
    for it in items[1:]:
        if len((cur + ", " + it).expandtabs(8)) > width:
            lines.append(cur + ",")
            cur = cont + it
        else:
            cur += ", " + it
    lines.append(cur + tail)
    return "\n".join(lines)


def block_comment(text, width=80):
    words, lines, cur = text.split(), [], " *"
    for w in words:
        if len(cur) + 1 + len(w) > width:
            lines.append(cur)
            cur = " *"
        cur += " " + w
    lines.append(cur)
    return "/*\n" + "\n".join(lines) + "\n */\n"


def generate(F, stmt, info, name, docarg):
    lo, hi = info["lo"], info["hi"]
    src = F.src
    ind_m = re.match(r"[ \t]*", src[src.rfind("\n", 0, lo) + 1:])
    indent = ind_m.group(0)
    fret = F.fn.result_type.spelling
    labels = []
    for _, lbl in info["gotos"]:
        if lbl not in labels:
            labels.append(lbl)
    need_outcome = bool(info["returns"] or labels)
    used = F.tokens
    oname = next(n for n in ("outcome", "block_outcome", name + "_outcome") if n not in used)
    rname = next(n for n in ("ret", "block_ret", name + "_ret") if n not in used)
    exit_label = name + "_exit"

    # mentions of by-reference locals become (*v_ref)
    refedits = []
    for cap in info["captured"]:
        if cap["mode"] == "ref":
            for a, b in cap["refs"]:
                refedits.append((a, b, "(*%s_ref)" % cap["decl"].spelling))

    def rewritten(a, b):
        """Source text [a, b) with the by-reference rewrites inside it."""
        t = src[a:b]
        for x, y, rep in sorted((e for e in refedits if a <= e[0] and e[1] <= b), reverse=True):
            t = t[:x - a] + rep + t[y - a:]
        return t

    # rewrite returns and gotos inside the block text
    edits = []
    for r in info["returns"]:
        semi = src.find(";", r.extent.end.offset - 1)
        if src[r.extent.end.offset:semi].strip():
            raise Refuse("cannot find the end of the return at line %d" % F.line_of(r.extent.start.offset))
        expr = rewritten(r.extent.start.offset + len("return"), semi).strip()
        if expr:
            rep = "{ *%s = (%s); %s = MXFS_BLOCK_RETURN; goto %s; }" % (rname, expr, oname, exit_label)
        else:
            rep = "{ %s = MXFS_BLOCK_RETURN; goto %s; }" % (oname, exit_label)
        edits.append((r.extent.start.offset, semi + 1, rep))
    for g, lbl in info["gotos"]:
        semi = src.find(";", g.extent.end.offset - 1)
        if src[g.extent.end.offset:semi].strip():
            raise Refuse("cannot find the end of the goto at line %d" % F.line_of(g.extent.start.offset))
        k = labels.index(lbl)
        rep = "{ %s = MXFS_BLOCK_GOTO + %d; goto %s; }" % (oname, k, exit_label)
        edits.append((g.extent.start.offset, semi + 1, rep))
    spans = [(a, b) for a, b, _ in edits]
    edits += [e for e in refedits
              if not any(a <= e[0] and e[1] <= b for a, b in spans)]
    body = src[lo:hi]
    for a, b, rep in sorted(edits, reverse=True):
        body = body[:a - lo] + rep + body[b - lo:]
    # the block moves from `indent` to one tab
    lines = body.split("\n")
    out = [lines[0]]
    for ln in lines[1:]:
        out.append("\t" + ln[len(indent):] if ln.startswith(indent) else ln)
    body = "\n".join(out)

    params, args, copy_in, copy_out = [], [], [], []
    for cap in info["captured"]:
        d = cap["decl"]
        pt = param_type(cap)
        if cap["mode"] == "copy":
            params.append(ptr_declarator(pt, d.spelling + "_io"))
            args.append("&" + d.spelling)
            copy_in.append("\t%s = *%s_io;" % (declarator(pt, d.spelling), d.spelling))
            copy_out.append("\t*%s_io = %s;" % (d.spelling, d.spelling))
        elif cap["mode"] == "ref":
            params.append(ptr_declarator(pt, d.spelling + "_ref"))
            args.append("&" + d.spelling)
        else:
            params.append(declarator(pt, d.spelling))
            args.append(d.spelling)
    has_value = bool(info["returns"]) and fret != "void"
    if has_value:
        params.append(ptr_declarator(fret, rname))
        args.append("&" + rname)

    rtype = "int" if need_outcome else "void"
    h = []
    lc = leading_comment(F, lo)
    doc = src[lc[0]:lc[1]] if lc else None
    if doc:
        dl = doc.rstrip("\n").split("\n")
        doc = "\n".join(l[len(indent):] if l.startswith(indent) else l.lstrip() for l in dl) + "\n"
        h.append(doc)
    elif docarg:
        h.append(block_comment(docarg))
    else:
        raise Refuse("the block has no comment above it; say what it does with --doc")
    h.append(wrap_list("static %s %s(" % (rtype, name), params or ["void"], ")", "") + "\n{\n")
    if need_outcome:
        h.append("\tint %s = MXFS_BLOCK_NEXT;\n" % oname)
    for ln in copy_in:
        h.append(ln + "\n")
    if need_outcome or copy_in:
        h.append("\n")
    h.append("\t" + body + "\n")
    if need_outcome:
        h.append("%s:\n" % exit_label)
    elif copy_out:
        h.append("\n")
    for ln in copy_out:
        h.append(ln + "\n")
    if need_outcome:
        h.append("\treturn %s;\n" % oname)
    h.append("}\n\n")
    helper = "".join(h)

    # the call that replaces the block
    if not need_outcome:
        site = wrap_list(name + "(", args, ");", indent).lstrip("\t ")
    else:
        inner = indent + "\t"
        parts = ["{"]
        parts.append(inner + "int %s;" % oname)
        if has_value:
            parts.append(inner + declarator(fret, rname) + ";")
        parts.append("")
        parts.append(wrap_list("%s = %s(" % (oname, name), args, ");", inner))
        if info["returns"]:
            parts.append(inner + "if (%s == MXFS_BLOCK_RETURN)" % oname)
            parts.append(inner + "\treturn%s;" % ((" " + rname) if has_value else ""))
        for k, lbl in enumerate(labels):
            parts.append(inner + "if (%s == MXFS_BLOCK_GOTO + %d)" % (oname, k))
            parts.append(inner + "\tgoto %s;" % lbl)
        parts.append(indent + "}")
        site = "\n".join(parts)
    return helper, site, lc


def main():
    global CFLAGS
    a = sys.argv[1:]
    if "--cflags" in a:
        i = a.index("--cflags")
        CFLAGS = a[i + 1]
        del a[i:i + 2]
    if len(a) < 3:
        print(__doc__)
        return 2
    path, fname = a[0], a[1]
    tu = parse(path)
    F = Func(tu, path, fname)
    if a[2] == "--list":
        mn = int(a[a.index("--min") + 1]) if "--min" in a else 40
        for c, anc, n in sorted(F.statements(mn), key=lambda x: x[0].extent.start.offset):
            depth = sum(1 for x in anc if x.kind == K.COMPOUND_STMT) - 1
            lc = leading_comment(F, c.extent.start.offset)
            note = ""
            if lc:
                note = re.sub(r"\s+", " ", re.sub(r"[/*]", " ", F.src[lc[0]:lc[1]])).strip()[:70]
            try:
                info = analyse(F, c, anc)
                caps = info["captured"]
                modes = [x["mode"] for x in caps]
                v = "OK  val=%d copy=%d ref=%d arr=%d ret=%d goto=%d" % (
                    modes.count("value"), modes.count("copy"), modes.count("ref"),
                    modes.count("array"), len(info["returns"]), len(info["gotos"]))
            except Refuse as e:
                v = "NO  " + str(e)
            print("%6d %5d d%d %-10s %s | %s" % (F.line_of(c.extent.start.offset), n, depth,
                                                 c.kind.name.replace("_STMT", ""), v, note))
        return 0
    if a[2] == "--batch":
        # LINE<TAB>NAME[<TAB>DOC] per line, all blocks of FUNCTION as the file
        # stands now.  Done from the bottom up: each helper lands above the
        # function, so every block still to do moves down by its length.
        jobs = []
        for raw in open(a[3]):
            if raw.strip() and not raw.startswith("#"):
                f = raw.rstrip("\n").split("\t")
                jobs.append((int(f[0]), f[1], f[2] if len(f) > 2 else None))
        shift = 0
        for ln, nm, doc in sorted(jobs, reverse=True):
            if shift:
                tu = parse(path)
                F = Func(tu, path, fname)
            rc, added = extract_one(F, fname, ln + shift, nm, doc, "--apply" in a)
            if rc:
                return rc
            shift += added
        return 0
    line, name = int(a[2]), a[3]
    docarg = a[a.index("--doc") + 1] if "--doc" in a else None
    return extract_one(F, fname, line, name, docarg, "--apply" in a)[0]


def extract_one(F, fname, line, name, docarg, apply):
    """Move the statement starting on `line`; (exit code, lines inserted)."""
    cand = [(c, anc) for c, anc, n in F.statements(1) if F.line_of(c.extent.start.offset) == line]
    if not cand:
        sys.exit("extract_block: no movable statement starts on line %d" % line)
    c, anc = min(cand, key=lambda x: len(x[1]))
    try:
        info = analyse(F, c, anc)
        helper, site, lc = generate(F, c, info, name, docarg)
    except Refuse as e:
        print("REFUSED: %s: %s" % (name, e))
        return 1, 0
    caps = info["captured"]
    modes = [x["mode"] for x in caps]
    print("%s: lines %d-%d -> %s(); captured: %d by value, %d copied in/out, %d by reference, "
          "%d arrays; %d return(s), %d goto(s)" % (
              fname, F.line_of(info["lo"]), F.line_of(info["hi"]), name, modes.count("value"),
              modes.count("copy"), modes.count("ref"), modes.count("array"),
              len(info["returns"]), len(info["gotos"])))
    if not apply:
        print(helper[:1500])
        print("--- call site ---")
        print(site)
        return 0, helper.count("\n")
    path = F.path
    src = F.src
    fstart = F.fn.extent.start.offset
    flc = leading_comment(F, fstart)
    ins = flc[0] if flc else src.rfind("\n", 0, fstart) + 1
    lo, hi = info["lo"], info["hi"]
    cut_lo = lc[0] if lc else lo
    if lc:
        ind = src[src.rfind("\n", 0, lo) + 1:lo]
        site = ind + site
        cut_lo = lc[0]
    new = src[:ins] + helper + src[ins:cut_lo] + site + src[hi:]
    open(path, "w", encoding="latin-1").write(new)
    print("applied")
    return 0, helper.count("\n")


if __name__ == "__main__":
    sys.exit(main())

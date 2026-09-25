#!/usr/bin/env python3
"""
Remove development-process bookkeeping from C comments: session tags
("sess41:", "(sess108)"), agent-run ids ("ccloop c7ee71c6"), and the names of
the models consulted for design reviews.  What a comment says about the code
stays; the note of which session wrote it goes.

    scripts/strip_process_notes.py [--check] FILE...

Only comment text is edited, and every comment keeps its line count, so the
compiled objects of a file are byte-identical before and after -- which is
how a run of this is verified (build both trees, compare the .o files).
Tokens joined by hyphens into a name ("ccloop-c7ee71c6-sess476-...", the
name of a stored note) are left alone so the pointer still resolves.
--check reports what would change and exits 1 if anything would.
"""
import re
import sys

SESS = r"(?<![\w-])sess(?:ion)?[-]?\d+[a-z0-9]*(?![\w-])"
RUN = r"(?<![\w-])ccloop(?:[ -]?[0-9a-f]{3,8})?(?![\w-])"

# Names of stored notes that were written as "ccloop-<run>-sess<N>-GPT-ruling-
# <subject>".  No note by any such name exists any more (the store names a
# note for what it teaches, not for when it was written), so the prefix is a
# dead pointer; the subject after it still says what the ruling was about.
NOTE_PREFIX = re.compile(r"(?:ccmemory[ \t]+)?ccloop-[0-9a-f]{4,8}-sess\d+[a-z0-9]*-"
                         r"(?:(?:GPT|Astra|Fable|Gemini)-)?(?:(?:ruling|consult|review)-)?")
# hyphenated forms the plain tag pattern leaves alone
HYPHENATED = [
    (re.compile(r"(?<![\w-])pre-sess\d+[a-z0-9]*(?![\w-])"), "earlier"),
    (re.compile(r"(?<![\w-])sess\d+[a-z]?-era\b"), "earlier"),
    (re.compile(r"(?<![\w-])sess\d+[a-z]?-\d+[a-z]?(?![\w-])[ \t]*"), ""),   # "sess122-124"
    (re.compile(r"(?<![\w-])sess\d+[a-z]?-(?=[A-Za-z])"), ""),               # "sess110-deleted"
    (re.compile(r"(?<![\w-])sess\d+[a-z0-9]*-GPT-"), ""),
]
MODEL_SUBS = [
    # the tail of a dead note name that wrapped onto its own comment line
    (r"(?<![\w-])(?:GPT|Astra|Fable|Gemini)-ruling-", ""),
    # "GPT-designed", "Gemini-confirmed", "Fable-guided"
    (r"(?<![\w-])(?:GPT|Astra|Fable|Gemini)-(?=[a-z])", "review-"),
    (r"(?<![\w-])GPT-5(?:\.\d)?\s+design-consult", "design-consult"),
    (r"(?<![\w-])GPT-5(?:\.\d)?\s+design", "design review"),
    (r"(?<![\w-])GPT-5(?:\.\d)?(?![\w-])", "design review"),
    (r"(?<![\w-])GPT[- ]ruled\b", "review-ruled"),
    (r"(?<![\w-])GPT[- ]endorsed\b", "review-endorsed"),
    (r"(?<![\w-])GPT[- ]reviewed\b", "reviewed"),
    (r"(?<![\w-])GPT ruling\b", "design-consult ruling"),
    (r"(?<![\w-])GPT review\b", "design review"),
    (r"(?<![\w-])GPT design\b", "design review"),
    (r"(?<![\w-])(?:GPT|Astra|Fable|Gemini)(?![\w-])", "design review"),
]


# "Sess29 v0.3.120: ...", "Sess35 prescription: ...", "Sess36+ task", "Sess21/hypothesis:"
# at the start of a sentence: the tag goes and the next word takes the capital,
# unless it is a version, a probe tag or an identifier
CAP_SESS = re.compile(r"(?<![\w-])Sess\d+[a-z]?\+?(?:/(?=[A-Za-z]))?[ \t]*")


def clean_caps(t):
    out, i = [], 0
    for m in CAP_SESS.finditer(t):
        out.append(t[i:m.start()])
        rest = t[m.end():]
        w = re.match(r"[a-z]+\b", rest)
        if w and not re.match(r"v\d", rest):
            out.append(rest[0].upper())
            i = m.end() + 1
        else:
            i = m.end()
    out.append(t[i:])
    return "".join(out)


def clean_comment(c):
    t = NOTE_PREFIX.sub("", c)
    for p, r in HYPHENATED:
        t = p.sub(r, t)
    t = clean_caps(t)
    # "sess3 (ccloop 46efd8b6):" / "(sess2, ccloop 8ba7ae5)" / "(ccloop)" and the like
    # Whitespace is matched as [ \t] only: a pattern that eats a newline
    # changes the comment's line count, and process() then keeps the whole
    # comment unedited (a tag ending a line used to survive that way).
    t = re.sub(r"\([ \t]*(?:(?:%s|%s)[ \t,;/]*)+\)" % (SESS, RUN), "", t)
    # "sess40's recycle path" -> "the recycle path" reads badly; drop the possessive with it
    t = re.sub(r"%s's[ \t]*" % SESS, "", t)
    # "mxfs sess19 (ccloop 4eef1f39): text" -> "text"
    t = re.sub(r"(?:mxfs[ \t]+)?%s(?:[ \t]*\([ \t]*(?:%s|[0-9a-f]{8})[ \t]*\))?[ \t]*:?[ \t]*" % (SESS, RUN), "", t)
    t = re.sub(r"(?:%s|%s)" % (SESS, RUN), "", t)
    for p, r in MODEL_SUBS:
        t = re.sub(p, r, t)
    # tidy what the removals left -- only on lines they touched, so a
    # comment's own alignment (tables, diagrams) is never reflowed
    out = []
    for line, orig in zip(t.split("\n"), c.split("\n")):
        if line == orig:
            out.append(line)
            continue
        m = re.match(r"^(\s*(?:/\*+|\*+|//)?\s?)(.*)$", line)
        lead, body = m.group(1), m.group(2)
        om = re.match(r"^(\s*(?:/\*+|\*+|//)?\s?)(.*)$", orig)
        if om.group(1) == lead and not om.group(2).startswith(" "):
            body = body.lstrip()        # space a removal left, not indentation
        body = re.sub(r"\(\s*[,;:/]*\s*\)", "", body)
        body = re.sub(r"\(\s*[,;]\s*", "(", body)
        body = re.sub(r"\s*[,;]?\s+\)|\s*[,;]\)", ")", body)
        body = re.sub(r"(?<=\S)[ ]{2,}(?=\S)", lambda mm: "  " if mm.start() and body[mm.start() - 1] in ".:" else " ", body)
        body = re.sub(r"^[:,;]\s*", "", body)
        body = re.sub(r"\s+([:,;.])(?=\s|$)", r"\1", body)
        body = body.rstrip()
        out.append(lead + body if body or not lead.strip() else lead.rstrip())
    return "\n".join(out)


def process(src):
    out = []
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        if c == "/" and i + 1 < n and src[i + 1] == "*":
            j = src.find("*/", i + 2)
            j = n if j < 0 else j + 2
            com = src[i:j]
            new = clean_comment(com)
            if new.count("\n") != com.count("\n") or not new.startswith("/*") or not new.endswith("*/"):
                new = com
            out.append(new)
            i = j
        elif c == "/" and i + 1 < n and src[i + 1] == "/":
            j = src.find("\n", i)
            j = n if j < 0 else j
            com = src[i:j]
            new = clean_comment(com)
            out.append(new if new.startswith("//") else com)
            i = j
        elif c in "\"'":
            j = i + 1
            while j < n and src[j] != c and src[j] != "\n":
                if src[j] == "\\":
                    j += 1
                j += 1
            lit = src[i:j + 1]
            # a string literal's text: messages, module parameter
            # descriptions, _Static_assert reasons; never an #include path
            line_start = src.rfind("\n", 0, i) + 1
            if c == '"' and not src[line_start:i].lstrip().startswith("#include"):
                body = clean_comment(lit[1:-1])
                if "\n" not in body and body.count("%") == lit[1:-1].count("%"):
                    lit = '"' + body + '"'
            out.append(lit)
            i = j + 1
        else:
            out.append(c)
            i += 1
    return "".join(out)


def main():
    args = sys.argv[1:]
    check = "--check" in args
    files = [a for a in args if a != "--check"]
    changed = 0
    for f in files:
        s = open(f, errors="replace").read()
        new = process(s)
        if new != s:
            if new.count("\n") != s.count("\n"):
                sys.stderr.write("%s: line count would change; left alone\n" % f)
                continue
            changed += 1
            if not check:
                open(f, "w").write(new)
    print("%d file(s) %s" % (changed, "would change" if check else "changed"))
    return 1 if (check and changed) else 0


if __name__ == "__main__":
    sys.exit(main())

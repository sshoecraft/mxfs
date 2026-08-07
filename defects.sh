#!/bin/bash
# defects.sh — read the RULE 6 defect ledger.
#
# THE LEDGER IS  tests/criteria/OPEN_DEFECTS.json  (JSON, not markdown).
# It is the single deterministic answer to "is MXFS production ready?":
# the `open_defects` board criterion FAILS while any entry is unresolved, so
# showstat can never read all-green while a credible defect is known-open.
#
# This script only READS.  Entries are edited by hand, and RULE 6 (CLAUDE.md)
# governs what may change: an entry leaves OPEN under exactly two dispositions,
# DISPROVED or FIXED AND VERIFIED.  Nothing here can close, delete, or reword a
# defect — that is deliberate.
#
# Three other consumers read the same file; all four MUST agree on what counts
# as closed, so the closure set below is a verbatim copy of theirs:
#   tests/suite/open_defects.sh  — the board criterion (the gate)
#   .ccloop/state.sh             — renders the severity-ordered queue into the
#                                  session-start prompt
#   showstat.sh                  — board display
#
# Usage:
#   ./defects.sh                     open defects, severity order — one line each
#   ./defects.sh -d                  the same queue with summary + next step
#   ./defects.sh D-PURGE             full entry for every id matching a substring
#   ./defects.sh -s critical         filter by severity
#   ./defects.sh -a | -c             include closed | only closed
#   ./defects.sh -t                  tally by severity and status
#   ./defects.sh -q                  bare ids, one per line (for scripting)
#   ./defects.sh -j D-FENCE          filtered entries as JSON
#   ./defects.sh -f                  full entries for the whole filtered set

set -u
LEDGER="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/tests/criteria/OPEN_DEFECTS.json"

if [ ! -r "$LEDGER" ]; then
    echo "defects.sh: cannot read $LEDGER" >&2
    exit 2
fi
if ! command -v python3 >/dev/null 2>&1; then
    echo "defects.sh: python3 required" >&2
    exit 2
fi

python3 - "$LEDGER" "$@" <<'PY'
import json, re, sys, os

LEDGER = sys.argv[1]
argv   = sys.argv[2:]

# Verbatim from tests/suite/open_defects.sh — ANY status not on this list,
# including a typo or a newly invented label, counts as OPEN.  A defect can
# never be closed by accident, only by an explicit RULE 6 disposition.
CLOSED = {"RESOLVED", "FIXEDANDVERIFIED", "FIXEDVERIFIED", "DISPROVED"}
norm   = lambda s: re.sub(r"[^A-Z0-9]", "", str(s).upper())
RANK   = {"critical": 0, "high": 1, "major": 2, "medium": 3, "minor": 4}
# Some entries carry a prose severity ("resource leak (on-disk slots) + ...").
# First word, lowercased — same reduction state.sh uses, so the two orderings
# are identical.  Anything unrecognised sorts last rather than being dropped.
sev    = lambda x: str(x.get("severity") or "unset").split()[0].lower().rstrip(":,;")

USAGE = """usage: defects.sh [-d|-f|-t|-q|-j] [-a|-c] [-s SEV] [ID-substring ...]

  (no args)      open defects in severity order, ONE LINE EACH (showstat style)
  ID-substring   full ledger entry for every matching id (case-insensitive)

  -d, --detail   the same queue, with each defect's summary and next step
  -f, --full     full entries for everything selected
  -t, --tally    counts by severity and status only
  -q, --quiet    ids only, one per line
  -j, --json     selected entries as JSON

  -a, --all      include closed entries      -c, --closed  only closed entries
  -s, --severity SEV                         -h, --help
"""

mode, scope, want_sev, pats = "table", "open", None, []
mode_set = False   # an explicit mode flag beats the id-lookup default below
i = 0
while i < len(argv):
    a = argv[i]
    if   a in ("-h", "--help"):     sys.stdout.write(USAGE); sys.exit(0)
    elif a in ("-d", "--detail"):   mode, mode_set = "list",  True
    elif a in ("-1", "--oneline"):  mode, mode_set = "table", True
    elif a in ("-f", "--full"):     mode, mode_set = "full",  True
    elif a in ("-t", "--tally"):    mode, mode_set = "tally", True
    elif a in ("-q", "--quiet"):    mode, mode_set = "quiet", True
    elif a in ("-j", "--json"):     mode, mode_set = "json",  True
    elif a in ("-a", "--all"):      scope = "all"
    elif a in ("-c", "--closed"):   scope = "closed"
    elif a in ("-s", "--severity"):
        i += 1
        if i >= len(argv):
            sys.stderr.write("defects.sh: -s needs a severity\n"); sys.exit(2)
        want_sev = argv[i].lower()
    elif a.startswith("-"):
        sys.stderr.write("defects.sh: unknown option %s\n\n%s" % (a, USAGE)); sys.exit(2)
    else:
        pats.append(a)
    i += 1

def flat(v, width=None):
    """Ledger values are str, list, or dict at arbitrary depth."""
    if isinstance(v, list):
        s = " ".join(flat(x) for x in v)
    elif isinstance(v, dict):
        s = "; ".join("%s=%s" % (k, flat(x)) for k, x in v.items())
    else:
        s = str(v)
    s = " ".join(s.split())
    if width and len(s) > width:
        s = s[:width - 1] + "…"
    return s

def note(msg, val):
    """Announce a widened search on stderr, return the rows so it can chain."""
    sys.stderr.write("defects.sh: %s\n\n" % msg)
    return val

def nextstep(x):
    for k in ("next", "next_step", "next_steps"):
        if x.get(k):
            return flat(x[k])
    return ""

def wrap(s, width, indent):
    out, line = [], ""
    for w in s.split():
        if line and len(line) + 1 + len(w) > width:
            out.append(line); line = w
        else:
            line = (line + " " + w).strip()
    if line:
        out.append(line)
    return ("\n" + indent).join(out)

d   = json.load(open(LEDGER))
ds  = d.get("defects", [])
is_open = lambda x: norm(x.get("status", "OPEN")) not in CLOSED

# The board's own arithmetic, computed before any filter, so the footer below
# always reprints the number the open_defects criterion will report.
n_open_total, n_total = sum(1 for x in ds if is_open(x)), len(ds)

sel = ds
if   scope == "open":   sel = [x for x in sel if is_open(x)]
elif scope == "closed": sel = [x for x in sel if not is_open(x)]
if want_sev:
    sel = [x for x in sel if sev(x) == want_sev]

# A bare argument selects by id substring, widening only as far as it must:
# id-in-scope, then id-anywhere (an id search must reach a CLOSED defect without
# -a, or looking up something you just closed silently returns nothing), then a
# full-text sweep — the ids are long and a half-remembered phrase from a session
# note is a legitimate way in.  Each widening says so, because "here are 2
# matches" means something different at each level.
if pats:
    low  = [p.lower() for p in pats]
    hit  = lambda pool, f: [x for x in pool if any(p in f(x) for p in low)]
    ident = lambda x: str(x.get("id", "")).lower()
    # Flatten values rather than searching raw JSON: a phrase that spans an
    # escaped newline or run of spaces in the file must still match.
    blob = lambda x: " ".join(flat(v) for v in x.values()).lower()

    sel = (hit(sel, ident)
           or (hit(ds, ident) and note("no id matched in scope=%s — showing id "
                                       "match(es) from the whole ledger" % scope,
                                       hit(ds, ident)))
           or (hit(sel, blob) and note("no id matched — showing full-text "
                                       "match(es) in scope=%s" % scope,
                                       hit(sel, blob)))
           or (hit(ds, blob) and note("no id matched — showing full-text "
                                      "match(es) from the whole ledger",
                                      hit(ds, blob))))
    if not sel:
        sys.stderr.write("defects.sh: nothing in the ledger matches %s\n"
                         % " ".join(repr(p) for p in pats))
        sys.exit(1)
    # An id/phrase lookup wants the ENTRY, not a row in a table -- but an
    # explicit -d/-1/-q/-j/-t on the command line still wins.
    if not mode_set:
        mode = "full"

sel.sort(key=lambda x: (RANK.get(sev(x), 5), str(x.get("id", ""))))

tty = sys.stdout.isatty() and os.environ.get("TERM", "") not in ("", "dumb")
def c(s, code):
    return "\033[%sm%s\033[0m" % (code, s) if tty else str(s)
SEVCOL = {"critical": "1;31", "high": "31", "major": "33", "medium": "33", "minor": "36"}

# A handful of entries put prose in `severity` ("resource leak (on-disk slots)
# + first-reaccess latency…").  Its first word is not a severity and printing it
# as one would invent a rank that entry never claimed, so the column says
# `other` and -f shows the real text.
label_sev = lambda x: sev(x) if (sev(x) in RANK or sev(x) == "unset") else "other"

if mode == "quiet":
    for x in sel:
        print(x.get("id", "?"))
    sys.exit(0)

if mode == "json":
    json.dump({"defects": sel}, sys.stdout, indent=2)
    sys.stdout.write("\n")
    sys.exit(0)

if mode == "tally":
    import collections
    bysev = collections.Counter(label_sev(x) for x in sel)
    bysta = collections.Counter(str(x.get("status", "OPEN")) for x in sel)
    print("%d of %d ledgered entries selected (scope=%s)\n" % (len(sel), n_total, scope))
    print("  by severity")
    for k in sorted(bysev, key=lambda k: RANK.get(k, 5)):
        print("    %-10s %3d" % (k, bysev[k]))
    print("\n  by status")
    for k, v in bysta.most_common():
        print("    %-22s %3d" % (k, v))
    print("\n  board cell: open=%d of=%d  (open_defects FAILS while open > 0)"
          % (n_open_total, n_total))
    sys.exit(0)

if mode == "full":
    # Field order that matches how a defect is actually read: what it is, then
    # what proves it, then what to do next.  Everything else follows in file
    # order so nothing a past session recorded is hidden.
    HEAD = ["id", "status", "severity", "opened", "found", "updated", "closed",
            "summary", "mechanism", "blast_radius", "scale"]
    TAIL = ["next", "next_step", "next_steps", "blocking_fix", "why_still_open",
            "containment", "detector", "verification", "fix", "disposition", "related"]
    for n, x in enumerate(sel):
        if n:
            print("\n" + "─" * 78 + "\n")
        print(c(x.get("id", "?"), "1"))
        print("  %-14s %s   %s" % ("status", c(x.get("status", "OPEN"), "1"),
                                   c("[%s]" % sev(x), SEVCOL.get(sev(x), "0"))))
        seen = {"id", "status", "severity"}
        for k in HEAD + TAIL + [k for k in x if k not in HEAD + TAIL]:
            if k in seen or k not in x or x[k] in (None, "", [], {}):
                continue
            seen.add(k)
            print("  %-14s %s" % (k, wrap(flat(x[k]), 92, " " * 17)))
    sys.exit(0)

label = {"open": "OPEN", "closed": "CLOSED", "all": "ALL"}[scope]
ncrit = sum(1 for x in sel if sev(x) == "critical")

def footer():
    if any(label_sev(x) == "other" for x in sel):
        print("(`other` = the entry's severity field holds prose, not a rank — "
              "./defects.sh -f shows it.)")
    print("open=%d of=%d ledgered — the exact figure tests/suite/open_defects.sh reports."
          % (n_open_total, n_total))
    print("RULE 6: an entry closes ONLY as DISPROVED or FIXED AND VERIFIED. 'Cannot")
    print("reproduce', a clean run, or a workaround are NOT dispositions.")

# ---- default: one line per defect, showstat-style ---------------------------
if mode == "table":
    import collections, shutil

    # `updated` is free-form across entries ("2026-08-04T10:19:13Z",
    # "2026-07-31 sess36", "sess32 (session 14) 2026").  Pull the ISO date out
    # of whichever field has one — a defect's age is worth a column, but only
    # if the column can never invent one.
    def when(x):
        for k in ("updated", "closed", "found", "opened"):
            m = re.search(r"\d{4}-\d{2}-\d{2}", flat(x.get(k, "")))
            if m:
                return m.group(0)
        return "—"

    def line1(x):
        """One line of prose for the row: what the defect IS."""
        return flat(x.get("summary") or x.get("mechanism") or
                    x.get("disposition") or x.get("evidence") or "")

    W_N   = max(3, len(str(len(sel))))
    W_SEV = max([8] + [len(label_sev(x)) for x in sel])
    W_ID  = max([2] + [len(str(x.get("id", "?"))) for x in sel])
    W_ST  = max([6] + [len(str(x.get("status", "OPEN"))) for x in sel])
    W_UPD = 10
    # The point of this mode is ONE line per defect, so the prose is ALWAYS
    # cut -- several summaries run past 700 chars and would swallow the table.
    # Fit the terminal when there is one, else a width that stays readable in
    # a pipe or a file.  -d and -f print the text in full.
    term  = shutil.get_terminal_size((0, 0)).columns if tty else 0
    used  = W_N + W_SEV + W_ID + W_ST + W_UPD + 5 * 3
    W_SUM = max(28, (term or (used + 97)) - used - 1)

    print("=== MXFS RULE 6 DEFECT LEDGER — %s, severity order  (%s) ===" %
          (label, os.path.relpath(LEDGER, os.getcwd())))
    print("%-*s | %-*s | %-*s | %-*s | %-*s | %s" %
          (W_N, "#", W_SEV, "SEVERITY", W_ID, "ID", W_ST, "STATUS",
           W_UPD, "UPDATED", "SUMMARY"))
    print("%s-+-%s-+-%s-+-%s-+-%s-+-%s" %
          ("-" * W_N, "-" * W_SEV, "-" * W_ID, "-" * W_ST, "-" * W_UPD,
           "-" * W_SUM))
    for n, x in enumerate(sel, 1):
        s  = label_sev(x)
        st = str(x.get("status", "OPEN"))
        print("%-*d | %s | %s | %s | %-*s | %s" %
              (W_N, n,
               c("%-*s" % (W_SEV, s), SEVCOL.get(s, "0")),
               c("%-*s" % (W_ID, x.get("id", "?")), "1"),
               c("%-*s" % (W_ST, st), "32" if not is_open(x) else "0"),
               W_UPD, when(x),
               flat(line1(x), W_SUM)))
    print("-" * (used + W_SUM))
    bysev = collections.Counter(label_sev(x) for x in sel)
    print("Total: %d — %s   [%s; ./defects.sh -d for each one's next step]" %
          (len(sel),
           ", ".join("%d %s" % (bysev[k], k)
                     for k in sorted(bysev, key=lambda k: RANK.get(k, 5))),
           label.lower()))
    footer()
    sys.exit(0)

# ---- -d/--detail: the queue with summary + next step ------------------------
print("%s defects — %d%s, severity order   (ledger: %s)\n"
      % (label, len(sel), (", %d critical" % ncrit) if ncrit else "",
         os.path.relpath(LEDGER, os.getcwd())))

for n, x in enumerate(sel, 1):
    s = label_sev(x)
    print("%2d. %s %s" % (n, c("[%-8s]" % s, SEVCOL.get(s, "0")), c(x.get("id", "?"), "1")))
    if mode == "oneline":
        continue
    summ = flat(x.get("summary") or x.get("mechanism") or "", 400)
    if summ:
        print("    %s" % wrap(summ, 88, " " * 4))
    nxt = nextstep(x)
    if nxt:
        print("    %s %s" % (c("next:", "2"), wrap(flat(nxt, 700), 88, " " * 4)))
    if x.get("status") and norm(x["status"]) != "OPEN":
        print("    status: %s" % x["status"])
    print()

footer()
PY

#!/usr/bin/env python3
"""The defect ledger: what is broken and still needs work.

THE ONE WAY IN OR OUT. This file is the only reader and the only writer of `data/defects.json`.
Hand-editing the JSON is how two sessions end up disagreeing about what is open, and how an entry
acquires a field nothing else understands.

IT IS A WORK QUEUE, NEVER AN ARCHIVE. A defect that is fixed is REMOVED and the fix becomes a
`CHANGELOG.md` entry. There is no closed status, no resolved status, no pending-verification status
-- an entry that had one would still be sitting in the queue telling every session it was work.

WHAT REPLACED WHAT. `defects.sh` was read-only by design, so adding an entry or transitioning one
meant hand-editing megabytes of JSON, which is why the `tools/ledger_*.py` files exist: written to
make single edits the reader could not. That whole shape is gone.

EVERY DEFECT NAMES THE CONFIGURATION IT REACHES. A defect observed only at 32 nodes on the CAW
transport does not block a 2-node TCP release, and a queue that cannot say so makes every release
wait on every defect -- which is how a queue stops being a queue and becomes a wall. Two fields
say it, and they DEFAULT TO BLOCKING EVERYTHING:

    nodes   the SMALLEST cluster the defect has been observed on.  1, 2, 4, 32...
            An entry with nodes=2 blocks a 2-node release and every larger one.
            An entry with nodes=32 blocks nothing smaller than 32.
    dlm     the transport the evidence is on: caw, tcp, or any.
            `any` blocks both.  It is the default, and it is the honest answer until
            someone has actually looked -- narrowing it is a claim about reach and
            needs the evidence to say so, exactly like a severity does.

Narrowing these fields DISPOSES OF NOTHING. It records which release an open defect blocks; the
defect stays open, stays in the queue, and still has to be fixed.

WHAT A RELEASE BAR IS, AND WHY IT IS NOT THE SAME AS REACH. `nodes`/`dlm` say which
configurations can exercise a defect. `impact` says whether the behaviour is one this release
refuses to ship: `integrity` (it corrupts or loses data), `stability` (it crashes, hangs or
shuts a node down), `verify` (the bar is unestablished and someone has to measure it), or
`noblock` (measured, and it does neither). `--release` keeps everything except `noblock`, so an
UNADJUDICATED record blocks -- deciding a record is harmless is a judgement someone makes and
signs, never a default. Setting it requires `--impact-why`, because "it does not corrupt data
and does not crash a node" is a claim about what was measured, and a bar set without one is the
relabel this queue exists to make impossible. Like a reach narrowing, an `impact` of `noblock`
DISPOSES OF NOTHING: the defect stays open, stays in the queue, and still has to be fixed.

    tools/defects.py                          the queue, severity order, one line each
    tools/defects.py -d                       the same queue with each one's next step
    tools/defects.py --at 2/tcp               only what blocks a 2-node TCP release
    tools/defects.py --at 2/tcp --release --gate    exit 1 while anything still blocks it
    tools/defects.py show <id>                one entry in full
    tools/defects.py add     -s high -m "..." [-N 2] [-D tcp] [-n "next step"] [-w "how it shows"]
    tools/defects.py update  <id> [-s ...] [-m ...] [-N ...] [-D ...] [-n ...] [-w ...]
    tools/defects.py update  <id> -I noblock --impact-why "what was measured"
    tools/defects.py remove  <id> --why "what was measured and what it said"
    tools/defects.py rename  <id> D-NEW-SHORTER-ID-0962   a new id, nothing else changes

AN ID IS AT MOST 80 CHARACTERS. It is minted from the summary, so a summary that opens with a
paragraph mints an id nobody can type, grep for or read in a one-line listing -- and truncating one
is not available, because evidence directories, memories and CHANGELOG entries already name the
record. Over the limit, `add` and `rename` REFUSE and ask for a name: pass `--id D-SHORT-NAME`.
    tools/defects.py --json                   the whole queue, for a script
"""
from __future__ import annotations

import argparse
import fcntl
import json
import os
import re
import signal
import sys
import time
from datetime import date
from pathlib import Path

#: `defects.py | head` closes the pipe under us, and python turns that into a traceback on stderr
#: plus a non-zero exit. Restoring the default disposition makes it exit quietly, the way every
#: other command in a pipeline does -- a queue nobody can pipe is a queue nobody greps.
try:
    signal.signal(signal.SIGPIPE, signal.SIG_DFL)
except (AttributeError, ValueError):
    pass

ROOT = Path(__file__).resolve().parents[1]
LEDGER = ROOT / "data" / "defects.json"

#: Ordered worst-first. Anything else sorts last rather than being dropped -- an unfamiliar severity
#: must never make a defect vanish out of the queue.
SEVERITIES = ("critical", "high", "major", "medium", "minor")

#: The transports a defect's evidence can be on. `any` is the fail-closed default: it blocks every
#: configuration, so an entry nobody has classified holds up every release rather than quietly
#: sliding out of one.
TRANSPORTS = ("any", "xfs", "caw", "cawd", "cawp", "tcp")

DEFAULT_NODES = 1
DEFAULT_DLM = "any"

#: HOW a record's reach was set, which is not the same question as what it was set to.
#:
#: A keyword sweep over a record's prose gives a useful number today; only reading the evidence
#: gives a number you can release on. Recording which one happened lets the queue report both,
#: instead of forcing a choice between a heuristic everyone half-trusts and a 93-record wall
#: nobody starts. `heuristic` is explicitly NOT an adjudication: a record whose text names CAW may
#: still reproduce over TCP, and the sweep only reports that the record does not say so.
REACH_SOURCES = ("default", "heuristic", "evidence")
DEFAULT_SOURCE = "default"

#: What this release refuses to ship, adjudicated per record. Absent means UNADJUDICATED, which
#: blocks -- the same fail-closed shape as an unexamined reach. `verify` is the honest answer when
#: the bar has not been measured yet: it blocks, and it says why it blocks.
IMPACTS = ("integrity", "stability", "verify", "noblock")

#: The bar values that are not a blocker for a release. Only one, and it is the only value that
#: takes a record OUT of `--release`, so it is the one that has to be earned.
IMPACT_CLEAR = ("noblock",)

FIELDS = {"severity": "s", "summary": "m", "next": "n", "evidence": "w",
          "nodes": "N", "dlm": "D", "impact": "I", "impact_why": "impact-why"}

#: Held across the whole read-modify-write of every mutating subcommand. The ledger is one JSON
#: document rewritten whole, so without this two concurrent `remove`s each read the same snapshot,
#: each write their own, and the later write silently resurrects the record the earlier one took
#: out -- both reporting success, in a file that carries no dates, so nothing afterwards shows it
#: happened. Measured 2026-09-17 on a copy of the real ledger.
LOCK = ROOT / "data" / ".defects.lock"
MUTATORS = ("add", "update", "remove", "rename")

#: A save measures ~6 ms on the real 858 KB ledger, so anything still holding the lock after this
#: long is wedged rather than busy, and saying so beats blocking a session forever.
LOCK_WAIT_SECONDS = 30

#: For `lift_config` only: what a leading bare `2 tcp` must not be mistaken for.
SUBCOMMANDS = ("show", "add", "update", "remove", "rename")
VALUE_FLAGS = ("-s", "--severity", "--at")

ORDERED = ("id", "severity", "nodes", "dlm", "opened", "updated", "summary", "evidence", "next")


#: The open lock file, kept for the process's lifetime so the lock is held until it exits. Nothing
#: reads it; binding it is what stops the handle being closed and the lock dropped mid-command.
lock_handle = None


def take_lock() -> None:
    """Hold an exclusive lock for the whole read-modify-write, or say who is holding it.

    A lock taken around `save` alone would not help: the window that loses a record opens at
    `load`, so the lock has to span both. Waiting is bounded rather than indefinite -- a holder
    that has not finished in far longer than a write takes is wedged, and a session told that can
    act, while one blocked forever inside a tool cannot.
    """
    global lock_handle
    LOCK.parent.mkdir(parents=True, exist_ok=True)
    lock_handle = LOCK.open("w")
    deadline = time.monotonic() + LOCK_WAIT_SECONDS
    announced = False
    while True:
        try:
            fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            return
        except OSError:
            if time.monotonic() >= deadline:
                sys.exit("defects: %s has been held by another defects.py for %ds. That is far "
                         "longer than a write takes, so it is wedged rather than busy: find the "
                         "holder before retrying." % (LOCK, LOCK_WAIT_SECONDS))
            if not announced:
                print("defects: waiting for another defects.py to finish writing the ledger…",
                      file=sys.stderr)
                announced = True
            time.sleep(0.05)


def load() -> dict:
    if not LEDGER.is_file():
        return {"defects": []}
    try:
        with LEDGER.open() as handle:
            data = json.load(handle)
    except ValueError as exc:
        #: Reachable without the lock only if something wrote the file by a path that is not this
        #: tool. Saying which file and what is wrong with it beats a bare traceback, because the
        #: reader's next move is to look at the file.
        raise SystemExit(f"defects: {LEDGER} is not valid JSON: {exc}")
    data.setdefault("defects", [])
    #: A record written by the earlier append path carries its later history in a stray
    #: `next_step` beside the canonical `next`. Fold it in, oldest first, so one field holds the
    #: whole investigation and a replace cannot lose half of it. The fold is saved by whatever
    #: mutator called `load`; a read-only listing sees the folded view without writing.
    for entry in data["defects"]:
        stray = entry.pop("next_step", None)
        if stray:
            have = entry.get("next") or ""
            entry["next"] = (have + " ===== " if have else "") + stray
    return data


def save(data: dict) -> None:
    """Atomically, so a concurrent READER never sees a half-written queue.

    The non-atomic version left an ~6 ms window per write in which `json.load` raised on a
    truncated document; a reader hitting it saw a corrupt ledger rather than the before or after
    state. The lock serialises writers; this makes readers safe without needing one.
    """
    LEDGER.parent.mkdir(parents=True, exist_ok=True)
    temporary = LEDGER.with_suffix(".json.tmp")
    with temporary.open("w") as handle:
        json.dump(data, handle, indent=2)
        handle.write("\n")
    os.replace(temporary, LEDGER)


def rank(entry: dict) -> tuple:
    severity = str(entry.get("severity", "")).lower()
    position = SEVERITIES.index(severity) if severity in SEVERITIES else len(SEVERITIES)
    return position, str(entry.get("id", ""))


def reach(entry: dict) -> tuple:
    """The configuration this defect has been observed on, with the fail-closed defaults applied.

    A missing field is not "unknown, so skip it" -- it is "nobody has established reach, so it
    blocks everything". Reading it any other way turns an unexamined entry into a silently
    narrowed one, which is the relabel this whole design exists to make impossible.
    """
    try:
        nodes = int(entry.get("nodes", DEFAULT_NODES))
    except (TypeError, ValueError):
        nodes = DEFAULT_NODES
    dlm = str(entry.get("dlm", DEFAULT_DLM)).lower()
    if dlm not in TRANSPORTS:
        dlm = DEFAULT_DLM
    return max(nodes, 1), dlm


def blocks(entry: dict, nodes: int, dlm) -> bool:
    """Does this defect block a release of the `nodes`/`dlm` configuration?

    It does if that configuration can exercise it: the cluster is at least as large as the
    smallest one the defect was seen on, and the transport matches or the defect is on both.
    A `dlm` of None means no transport was named, so every transport counts.
    """
    seen_nodes, seen_dlm = reach(entry)
    if seen_nodes > nodes:
        return False
    if dlm is None:
        return True
    return seen_dlm in ("any", str(dlm).lower())


def parse_at(text: str) -> tuple:
    """`2/tcp`, or a bare `2` meaning every transport at that size.

    Same notation as the board, the run keys and showstat.sh. A tool that spells the cluster a
    different way from the harness is one nobody types correctly the first time.
    """
    match = re.fullmatch(r"\s*(\d+)\s*(?:/\s*([A-Za-z]+))?\s*", str(text))
    if not match:
        sys.exit(f"defects: wanted NODES or NODES/TRANSPORT such as 2 or 2/tcp, not {text!r}")
    nodes = int(match.group(1))
    dlm = match.group(2).lower() if match.group(2) else None
    if nodes < 1:
        sys.exit("defects: node count must be at least 1")
    if dlm is not None and dlm not in TRANSPORTS:
        sys.exit(f"defects: transport {dlm!r}; expected one of {list(TRANSPORTS)}")
    return nodes, dlm


def gate_label(gate: tuple) -> str:
    nodes, dlm = gate
    return "%d-node" % nodes if dlm is None else "%d/%s" % (nodes, dlm)


def lift_config(argv: list) -> list:
    """Accept `defects.py 2 tcp` and `defects.py 2/tcp`, the way `showstat.sh 2 tcp` always has.

    A session names the configuration far more often than it names a subcommand, and having to
    remember `--at` for the common case is how a tool stops being reached for. The leading
    argument is a configuration only when it starts with digits, so it can never shadow `show`,
    `add`, `update` or `remove`.
    """
    rest, skip = list(argv[1:]), False
    for index, token in enumerate(rest):
        if skip:
            skip = False
            continue
        if token in SUBCOMMANDS:
            break
        if token.startswith("-"):
            #: A flag that takes a value would otherwise have its value read as a node count:
            #: `-s 2` is a severity, not a cluster.
            skip = token in VALUE_FLAGS
            continue
        match = re.fullmatch(r"(\d+)(?:/([A-Za-z]+))?", token)
        if not match:
            break
        nodes, dlm, consumed = match.group(1), match.group(2), 1
        if dlm is None and index + 1 < len(rest) and rest[index + 1].lower() in TRANSPORTS:
            dlm, consumed = rest[index + 1], 2
        spec = nodes if dlm is None else "%s/%s" % (nodes, dlm)
        return argv[:1] + rest[:index] + ["--at", spec] + rest[index + consumed:]
    return argv


def tally(entries: list) -> str:
    """`68 critical, 21 high, 4 major` -- worst first, and an unfamiliar severity is still counted.

    A count by severity is the only line most sessions read. Dropping a severity the tool does not
    recognise would silently shrink the queue, so anything unexpected is named and counted where
    it falls rather than folded into a total that no longer adds up.
    """
    counts: dict[str, int] = {}
    for entry in entries:
        counts[str(entry.get("severity", "unset")).lower()] = \
            counts.get(str(entry.get("severity", "unset")).lower(), 0) + 1
    order = [s for s in SEVERITIES if s in counts] + \
            sorted(k for k in counts if k not in SEVERITIES)
    return ", ".join("%d %s" % (counts[k], k) for k in order)


def source_of(entry: dict) -> str:
    value = str(entry.get("reach_source", DEFAULT_SOURCE)).lower()
    return value if value in REACH_SOURCES else DEFAULT_SOURCE


def config_of(entry: dict) -> str:
    """`2/tcp` confirmed from evidence, `2/tcp?` set by the keyword sweep, `1/any` never looked at.

    The question mark is the whole point of recording provenance: a heuristic reach is a useful
    number and a weak claim, and the queue has to be able to show both at once without the reader
    having to remember which records were adjudicated.
    """
    seen_nodes, seen_dlm = reach(entry)
    mark = "?" if source_of(entry) == "heuristic" else ""
    return "%d/%s%s" % (seen_nodes, seen_dlm, mark)


#: An id is something a person types, greps for, and reads in a one-line queue listing. Past the
#: eighties it stops being a name and starts being the summary again: a 104-character id pushed
#: every other column off the terminal and had to be quoted by hand in every message about it.
#: The limit is a refusal and never a truncation -- silently cutting an id would break every
#: evidence directory, memory and CHANGELOG entry that already refers to the record by name.
MAX_ID = 80


def check_id(new_id: str) -> str:
    """The one gate every id passes, whether minted or given."""
    if len(new_id) > MAX_ID:
        sys.exit("defects: the id is %d characters and the limit is %d:\n  %s\n"
                 "Choose a shorter one with --id: name the defect, do not restate the summary."
                 % (len(new_id), MAX_ID, new_id))
    return new_id


def mint(summary: str, taken) -> str:
    """An id from the summary, because a defect nobody can name is one nobody discusses.

    The old ledger's ids were written by hand and read well -- `D-THE-TRAINER-OPTION-NAMES-A-TRAINER
    -OF-THE-WRONG-CLASS` says what is wrong without opening the entry. This keeps that shape without
    asking for it twice.

    It does NOT shorten a long summary into a fitting id. Dropping words picks the name by counting
    characters, and the word it drops is as likely to be the one that distinguishes this record from
    its neighbour as not. A summary too long to name itself is handed back for a name.
    """
    words = re.findall(r"[A-Za-z0-9]+", summary.upper())[:9]
    base = "D-" + "-".join(words) if words else "D-UNNAMED"
    candidate, suffix = base, 2
    while candidate in taken:
        candidate = f"{base}-{suffix}"
        suffix += 1
    return check_id(candidate)


def find(data: dict, wanted: str) -> dict:
    """By exact id, else by unique substring -- ids are long and typing one in full is a chore."""
    wanted = wanted.strip()
    for entry in data["defects"]:
        if str(entry.get("id", "")) == wanted:
            return entry
    low = wanted.lower()
    hits = [e for e in data["defects"] if low in str(e.get("id", "")).lower()]
    if len(hits) == 1:
        return hits[0]
    if not hits:
        sys.exit(f"defects: no entry matches {wanted!r}")
    sys.exit("defects: %r matches %d entries:\n  %s"
             % (wanted, len(hits), "\n  ".join(str(e["id"]) for e in hits)))


def flat(text, width: int) -> str:
    """One line, truncated. Summaries here run to a couple of thousand characters, and a queue
    that wraps every one of them across four lines is a queue nobody scans."""
    line = " ".join(str(text).split())
    return line[:width - 1] + "…" if len(line) > width else line


def wrap(text: str, width: int, indent: str) -> str:
    out, line = [], ""
    for word in str(text).split():
        if line and len(line) + 1 + len(word) > width:
            out.append(line)
            line = word
        else:
            line = (line + " " + word).strip()
    if line:
        out.append(line)
    return ("\n" + indent).join(out)


def show_one(entry: dict) -> None:
    print(entry.get("id", "?"))
    print("  %-10s %s" % ("severity", entry.get("severity", "unset")))
    if entry.get("impact"):
        print("  %-10s %s — %s" % ("bar", entry["impact"], wrap(entry.get("impact_why",""), 80, " "*13)))
    print("  %-10s %s%s" % ("observed", config_of(entry),
                            "" if "nodes" in entry and "dlm" in entry
                            else "   (defaulted -- reach not established, blocks every release)"))
    for key in ("opened", "updated"):
        if entry.get(key):
            print("  %-10s %s" % (key, entry[key]))
    for key in ("summary", "evidence", "next"):
        if entry.get(key):
            print("  %-10s %s" % (key, wrap(entry[key], 88, " " * 13)))
    for key, value in entry.items():
        if key not in ORDERED:
            print("  %-10s %s" % (key, wrap(value, 88, " " * 13)))


def cmd_list(data: dict, args) -> int:
    entries = sorted(data["defects"], key=rank)
    total = len(entries)
    if args.severity:
        entries = [e for e in entries if str(e.get("severity", "")).lower() == args.severity]
    gate = None
    if args.at:
        gate = parse_at(args.at)
        entries = [e for e in entries if blocks(e, *gate)]
    if args.release:
        #: THE RELEASE BAR: 100% data integrity, and stability (no crashes, hangs, shutdowns or
        #: unmountable volumes). Anything that is neither is not a blocker for THIS release --
        #: pace, cosmetics, and defects unreachable in the shipping configuration.
        #:
        #: An UNADJUDICATED record blocks, exactly as an unclassified reach does. Deciding a
        #: record is harmless is a judgement someone has to make and be accountable for; it is
        #: never the default.
        entries = [e for e in entries if str(e.get("impact", "")).lower() != "noblock"]
    #: THE ONLY LIST PATH THAT CAN FAIL, AND ONLY WHEN ASKED. Every other one exits 0 whether it
    #: printed 16 records or none, so a script could not tell "clear" from "still blocked" without
    #: parsing the output -- which is how a release gate ends up grepping prose. `--gate` makes the
    #: emptiness of the filtered queue the exit status, and it is opt-in so that no existing caller
    #: starts failing because its queue is not empty.
    verdict = 1 if (args.gate and entries) else 0
    if args.json:
        json.dump({"defects": entries}, sys.stdout, indent=2)
        sys.stdout.write("\n")
        return verdict
    if not entries:
        print("no open defects." if not gate
              else "nothing in the queue blocks a %s release (%d open overall)."
                   % (gate_label(gate), total))
        return verdict

    width_id = max(len(str(e.get("id", "?"))) for e in entries)
    width_sev = max(len(str(e.get("severity", "unset"))) for e in entries)
    width_cfg = max(len(config_of(e)) for e in entries)
    #: The rule under the queue is drawn to what was actually printed, not to a guess at the
    #: summary column. A rule wider than the terminal wraps and puts a stray line of dashes under
    #: the total, which reads as a second, empty section.
    ruler = 0
    for number, entry in enumerate(entries, 1):
        head = ("%2d. %-*s  %-*s  %-*s  %s"
                % (number, width_sev, entry.get("severity", "unset"),
                   width_cfg, config_of(entry),
                   width_id, entry.get("id", "?"),
                   "" if args.detail else flat(entry.get("summary", ""), 100)))
        ruler = max(ruler, max(len(line) for line in head.splitlines()))
        print(head)
        if args.detail:
            print("    %s" % wrap(entry.get("summary", ""), 92, " " * 4))
            if entry.get("next"):
                print("    next: %s" % wrap(entry["next"], 86, " " * 10))
            print()
    print("-" * ruler)
    kinds: dict[str, int] = {}
    for e in entries:
        kinds[str(e.get("impact", "unadjudicated")).lower()] = \
            kinds.get(str(e.get("impact", "unadjudicated")).lower(), 0) + 1
    firm = sum(1 for e in entries if source_of(e) == "evidence")
    guess = sum(1 for e in entries if source_of(e) == "heuristic")
    blind = len(entries) - firm - guess
    if gate:
        print("Total: %d of %d open block a %s release — %s"
              % (len(entries), total, gate_label(gate), tally(entries)))
    else:
        print("Total: %d open — %s" % (len(entries), tally(entries)))
    #: A gate number is only as good as how its members got there, so the split is printed with it
    #: rather than left for someone to go and check.
    order = [k for k in ("integrity", "stability", "verify", "noblock", "unadjudicated")
             if k in kinds]
    if order:
        print("       bar:   %s" % ", ".join("%d %s" % (kinds[k], k) for k in order))
    print("       reach: %d from evidence, %d from the keyword sweep (marked ?), %d never examined"
          % (firm, guess, blind))
    if verdict:
        print("GATE: %d record%s still block%s a %s release."
              % (len(entries), "" if len(entries) == 1 else "s",
                 "s" if len(entries) == 1 else "",
                 gate_label(gate) if gate else "any"))
    return verdict


def cmd_show(data: dict, args) -> int:
    show_one(find(data, args.id))
    return 0


def check_impact(value, why) -> None:
    """A bar is a claim about what was measured, so it does not get set without the measurement.

    `noblock` is the only value that takes a record out of `--release`, which makes it the one
    worth a guard -- but every value gets the same one, because "we have not looked" is also
    something a later reader needs stated rather than inferred from a blank field.
    """
    if value is None:
        return
    if str(value).lower() not in IMPACTS:
        sys.exit(f"defects: impact {value!r}; expected one of {list(IMPACTS)}")
    if not str(why or "").strip():
        sys.exit("defects: -I/--impact needs --impact-why saying what was measured and what it "
                 "said. A bar recorded without one is a relabel, not an adjudication.")


def cmd_add(data: dict, args) -> int:
    if not args.summary:
        sys.exit("defects: add needs -m/--summary saying what is broken")
    check_impact(args.impact, args.impact_why)
    severity = (args.severity or "medium").lower()
    if severity not in SEVERITIES:
        sys.exit(f"defects: severity {severity!r}; expected one of {list(SEVERITIES)}")
    if args.nodes is not None and args.nodes < 1:
        sys.exit("defects: -N/--nodes is the smallest cluster it was seen on; at least 1")

    taken = {str(e.get("id", "")) for e in data["defects"]}
    entry = {"id": check_id(args.id.strip()) if args.id else mint(args.summary, taken),
             "severity": severity,
             "nodes": DEFAULT_NODES if args.nodes is None else args.nodes,
             "dlm": (args.dlm or DEFAULT_DLM).lower(),
             "opened": date.today().isoformat(),
             "summary": args.summary}
    if entry["id"] in taken:
        sys.exit(f"defects: {entry['id']} already exists")
    if args.evidence:
        entry["evidence"] = args.evidence
    if args.next:
        entry["next"] = args.next
    if args.impact:
        entry["impact"] = str(args.impact).lower()
        entry["impact_why"] = args.impact_why

    data["defects"].append(entry)
    save(data)
    print(f"added {entry['id']}  ({config_of(entry)})")
    return 0


def cmd_update(data: dict, args) -> int:
    entry = find(data, args.id)
    changed = []
    for field in FIELDS:
        value = getattr(args, field if field != "next" else "next_step", None)
        if value is not None and value != "":
            entry[field] = value.lower() if field in ("dlm", "impact") else value
            changed.append(field)
    #: A record's next step is its investigation, oldest finding first; every
    #: session so far rebuilt it by hand as "old ===== new" because -n replaces.
    #: The separator is the one those hand-built records already use.
    #: It appends to `next`, the field every other path reads and prints. An earlier version wrote
    #: a separate `next_step`, which `-n` then silently left in place while replacing `next`, so a
    #: record could carry two next-step histories and a replace could destroy the canonical one
    #: while the caller checked the stray one. `load` folds any such field back into `next`.
    appended = getattr(args, "append_next", None)
    if appended:
        have = entry.get("next") or ""
        entry["next"] = (have + " ===== " if have else "") + appended
        changed.append("next")
    if not changed:
        sys.exit("defects: update needs at least one of -s/-m/-n/-a/-w/-N/-D/-I")
    #: Checked against what the record will HOLD, not only against what this call passed, so that
    #: `-I noblock` on a record whose reason was written earlier is accepted while `-I noblock` with
    #: no reason anywhere is not.
    if "impact" in changed:
        check_impact(entry["impact"], entry.get("impact_why"))
    elif "impact_why" in changed and not entry.get("impact"):
        sys.exit("defects: --impact-why is the reason for a bar, and this record has none. "
                 "Set both, with -I/--impact.")
    #: Setting reach BY HAND means someone read the record. That is the only thing that upgrades a
    #: heuristic guess to a claim the release gate can rest on.
    if "nodes" in changed or "dlm" in changed:
        entry["reach_source"] = "evidence"
    if "severity" in changed and str(entry["severity"]).lower() not in SEVERITIES:
        sys.exit(f"defects: severity {entry['severity']!r}; expected one of {list(SEVERITIES)}")
    if "nodes" in changed and int(entry["nodes"]) < 1:
        sys.exit("defects: -N/--nodes is the smallest cluster it was seen on; at least 1")
    entry["updated"] = date.today().isoformat()
    save(data)
    print(f"updated {entry['id']}: {', '.join(changed)}  ({config_of(entry)})")
    return 0


def cmd_remove(data: dict, args) -> int:
    """A defect leaves ONLY on evidence, and what leaves is written down somewhere else.

    `--why` IS NOT OPTIONAL. An entry that cannot say what was measured is not fixed, and removing
    it without that is how a known defect becomes a "known limitation" by attrition -- which is the
    whole reason the ledger exists.
    """
    entry = find(data, args.id)
    if not args.why:
        sys.exit("defects: remove needs --why saying what was measured and what it said")
    data["defects"] = [e for e in data["defects"] if e is not entry]
    save(data)

    print(f"removed {entry['id']}")
    print("\nThe fix belongs in CHANGELOG.md. Paste this under today's version:\n")
    print(f"- **{entry.get('summary', entry['id'])}** — {args.why}")
    return 0


def cmd_rename(data: dict, args) -> int:
    """A new id for an existing record; nothing else about it changes.

    Ids are minted from the summary and can run to a dozen words, which nobody types and nobody
    reads in a queue listing.  The numeric suffix (`-0962`) is how evidence directories, memories
    and CHANGELOG entries refer to a record, so a rename that drops it must be deliberate: the tool
    warns and keeps going, because the id is the user's to choose.
    """
    entry = find(data, args.id)
    new_id = args.new_id.strip()
    if not re.fullmatch(r"D-[A-Z0-9][A-Z0-9-]*", new_id):
        sys.exit(f"defects: {new_id!r} is not an id of the form D-WORDS-LIKE-THIS[-0962]")
    check_id(new_id)
    if any(str(e.get("id", "")) == new_id for e in data["defects"]):
        sys.exit(f"defects: {new_id} already exists")
    old_id = str(entry.get("id", ""))
    old_suffix = re.search(r"-(\d{3,4})$", old_id)
    if old_suffix and not new_id.endswith("-" + old_suffix.group(1)):
        print(f"warning: {old_id} ends in -{old_suffix.group(1)} and {new_id} does not; "
              "evidence directories and CHANGELOG entries refer to it by that number")
    entry["id"] = new_id
    entry["updated"] = date.today().isoformat()
    save(data)
    print(f"renamed {old_id}\n     -> {new_id}  ({config_of(entry)})")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="what is broken and still needs work",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__.split("    tools/defects.py")[0].strip())
    parser.add_argument("-d", "--detail", action="store_true",
                        help="include each one's next step")
    parser.add_argument("-s", "--severity", help="filter the queue by severity")
    parser.add_argument("--at", metavar="NODES/DLM",
                        help="only what blocks that release configuration, e.g. 2/tcp. "
                             "May also be given bare: `defects.py 2 tcp`")
    parser.add_argument("--release", action="store_true",
                        help="only what blocks a release: data integrity and stability. "
                             "An unadjudicated record blocks.")
    parser.add_argument("--gate", action="store_true",
                        help="exit 1 if anything is left after the filters, 0 if nothing is. "
                             "Without it every list exits 0, empty or not.")
    parser.add_argument("--json", action="store_true", help="the queue as JSON")

    subs = parser.add_subparsers(dest="command")

    show = subs.add_parser("show", help="one entry in full")
    show.add_argument("id")

    add = subs.add_parser("add", help="record a new defect")
    add.add_argument("-s", "--severity", default="medium", choices=SEVERITIES)
    add.add_argument("-m", "--summary", required=True, help="what is broken")
    add.add_argument("-w", "--evidence", help="how it shows, and what was measured")
    add.add_argument("-n", "--next", help="the next step")
    add.add_argument("-N", "--nodes", type=int,
                     help="smallest cluster it was observed on (default %d)" % DEFAULT_NODES)
    add.add_argument("-D", "--dlm", choices=TRANSPORTS,
                     help="transport the evidence is on (default %s)" % DEFAULT_DLM)
    add.add_argument("-I", "--impact", choices=IMPACTS,
                     help="the release bar this behaviour crosses; absent blocks every release")
    add.add_argument("--impact-why", dest="impact_why",
                     help="what was measured that establishes that bar; required with -I")
    add.add_argument("--id", help="override the generated id; at most %d characters. "
                     "Required when the summary is too long to name itself." % MAX_ID)

    update = subs.add_parser("update", help="change an entry")
    update.add_argument("id")
    update.add_argument("-s", "--severity", choices=SEVERITIES)
    update.add_argument("-m", "--summary")
    update.add_argument("-w", "--evidence")
    update.add_argument("-n", "--next", dest="next_step")
    update.add_argument("-a", "--append-next", dest="append_next",
                        help="append to the next step after a ' ===== ' separator instead of "
                             "replacing it")
    update.add_argument("-N", "--nodes", type=int,
                        help="smallest cluster it was observed on")
    update.add_argument("-D", "--dlm", choices=TRANSPORTS,
                        help="transport the evidence is on")
    update.add_argument("-I", "--impact", choices=IMPACTS,
                        help="the release bar this behaviour crosses; %s is the only value that "
                             "takes a record out of --release" % IMPACT_CLEAR[0])
    update.add_argument("--impact-why", dest="impact_why",
                        help="what was measured that establishes that bar; required with -I")

    remove = subs.add_parser("remove", help="it is fixed or it was never real")
    remove.add_argument("id")
    remove.add_argument("--why", required=True,
                        help="what was measured and what it said")

    rename = subs.add_parser("rename", help="give an entry a new id; nothing else changes")
    rename.add_argument("id")
    rename.add_argument("new_id", help="the new id, D-WORDS-LIKE-THIS-0962 (keep the number); "
                        "at most %d characters" % MAX_ID)

    args = parser.parse_args(lift_config(sys.argv)[1:])
    for missing in ("at", "release", "gate", "nodes", "dlm", "next_step", "summary", "evidence",
                    "id", "next", "impact", "impact_why"):
        if not hasattr(args, missing):
            setattr(args, missing, None)
    #: BEFORE `load`, because the window that loses a record spans the read as well as the write.
    #: Read-only paths do not take it: `save` is atomic, so a reader sees the before or the after
    #: state and never a torn document, and making every listing contend for a lock would make the
    #: one command every session runs able to block.
    if args.command in MUTATORS:
        take_lock()
    data = load()

    if args.command == "show":
        return cmd_show(data, args)
    if args.command == "add":
        return cmd_add(data, args)
    if args.command == "update":
        return cmd_update(data, args)
    if args.command == "remove":
        return cmd_remove(data, args)
    if args.command == "rename":
        return cmd_rename(data, args)
    return cmd_list(data, args)


if __name__ == "__main__":
    sys.exit(main())

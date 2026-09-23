#!/usr/bin/env python3
"""The board: what MXFS MUST ACHIEVE, and whether it does yet.

    tools/criteria.py                     the board, every configuration
    tools/criteria.py --at 2/tcp          the board for ONE release configuration
    tools/criteria.py -v                  add each criterion's requirement and why
    tools/criteria.py show <id>           one criterion in full, every configuration's cell
    tools/criteria.py --gaps              criteria nothing can measure -- wishes, not criteria
    tools/criteria.py add    -i ID -r "requirement" -d "detector" [-b BUDGET_S] [-p PHASE]
    tools/criteria.py update <id> --at 2/tcp -s PASS -m "measured" [-e ELAPSED_S] [--build SRCVER]
    tools/criteria.py remove <id> --why "why this is no longer something we must achieve"

THE ONE WAY IN OR OUT. This file is the only reader and the only writer of `data/criteria.json`.
It was read-only for its whole life as `showstat.sh`, which is why the only thing that could write
a cell was a flag buried in one test harness -- and why the file was otherwise edited by hand.

CRITERIA AND DEFECTS ARE DIFFERENT LISTS AND MUST STAY APART. A criterion is the SPECIFICATION --
permanent, and it can regress. A defect is transient and leaves the queue when it is fixed
(`tools/defects.py`). Printing defects on this board made it about what is broken instead of about
what must be true, and it is why `open_defects` sat on the board as a criterion that can never go
green: it was the defect queue wearing a criterion's clothes. Ask the queue what blocks a release
-- `tools/defects.py --at 2/tcp` -- and ask this board whether the requirements are met. `remove`
here is for a criterion that is no longer something we must achieve, NOT for one that now passes:
a passing criterion stays on the board so its regression is visible.

EVERY CRITERION IS PROVED ONE CONFIGURATION AT A TIME. A green on 32/caw says nothing about 2/tcp:
different transport, different node count, different code paths. So every cell is per configuration
and a criterion is UNKNOWN for every configuration absent from its map. That is the whole content of
"only the 32-node columns are measured" -- a board that hid the empty columns would have read green.
The top-level status is PASS only when every configuration in CONFIGS has one.

EVERY CRITERION CARRIES A TIME BUDGET, AND OVERRUNNING IT IS A FAILURE. A timeout is not a flaky
run and a slow pass is not a pass: the budget is a performance assertion, so `update` records FAIL
when the elapsed time exceeds it, whatever status the caller passed and even with zero errors.
Widening a budget to make a cell green is the one edit this file exists to make visible.

EVERY CRITERION MUST HAVE A DETECTOR. A requirement nobody can measure is a wish. `add` refuses
without one, and `--gaps` finds any that predate that refusal.

AND NAMING A DETECTOR IS NOT HAVING ONE. A `--gaps` that only asks whether the field is filled in
will report "every criterion has a detector" while naming files that have never existed. It resolves
any detector that names a path and reports the ones that are not there, because the single guarantee
this board makes about itself must not be the one thing it does not check.

NOTHING HERE RE-RUNS ANYTHING. Each cell records the BUILD it was earned on and AGES: a green earned
before a change landed says nothing about the build after it. Staleness is displayed, never hidden,
because a board that quietly reprints last week's green is worse than no board at all.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import signal
import sys
from datetime import date, datetime, timezone
from pathlib import Path

#: `criteria.py | head` closes the pipe under us, and python turns that into a traceback on stderr
#: plus a non-zero exit. Restoring the default disposition makes it exit quietly, the way every
#: other command in a pipeline does.
try:
    signal.signal(signal.SIGPIPE, signal.SIG_DFL)
except (AttributeError, ValueError):
    pass

ROOT = Path(__file__).resolve().parents[1]

#: `MXFS_CRIT` points at a different board file, so a second rig's results can be kept off the
#: primary board without a second copy of this tool.
CRITERIA = Path(os.environ["MXFS_CRIT"]) if os.environ.get("MXFS_CRIT") \
    else ROOT / "data" / "criteria.json"

#: A status this board does not recognise is NOT green. Nothing passes by typo or by inventing a
#: label -- an unknown string paints as a warning and never as a pass.
MARK = {
    "PASS": "32",
    "FAIL": "1;31",
    "FLAKY": "1;33",
    "BLOCKED": "1;31",
    "ABORTED": "1;31",
    "SKIP": "33",
    "NOT RUN": "33",
    "NOT STARTED": "33",
    "UNKNOWN": "33",
    "STALE": "33",
    "PARTIAL": "33",
    #: A LIVE-RUN STATE ONLY. A cell must never still be PENDING when no run is executing: a run
    #: that started a test and then died did not produce a result, and `finalize` converts every
    #: marker it left into ABORTED (was in flight) or NOT RUN (never reached).
    "PENDING": "1;36",
}
STATUSES = tuple(MARK)

#: How many previous verdicts a cell keeps. The flake window is 11 including the live cell, so ten
#: is exactly what that rule can see.
HISTORY_DEPTH = 10

#: FLAKY IS NOT A PASS. A cell that passes now but whose own test detected a fault in a recent run
#: is a defect nobody has rooted yet, and the queue is where it belongs. It is listed here so it
#: paints, never so it counts toward the bar.
GREEN = ("PASS",)

#: FLAKY means exactly one thing: the TEST ITSELF detected a fault on a formed cluster in a recent
#: run, and that incident has not aged out. A cell stays FLAKY until the window is clean or the
#: defect is fixed -- a flake is a defect to fix, not a label to launder.
#:
#: What it must NOT mean is "the rig broke that day". A failure whose recorded reason is
#: rig-formation is not evidence of an MXFS fault and never enters the flake count, and the two
#: tests that ARE the rig-forming step and the policy gate never flake at all.
RIG_NOISE = re.compile(r"pre-assert|NO_TERMINAL_RECORD|run was killed|prep fail", re.I)
FLAKE_WINDOW = 11
NEVER_FLAKE = ("prep_cluster", "open_defects")

#: Every configuration MXFS claims to support. A criterion proved on 32/caw says nothing about
#: 2/tcp, so a criterion is UNKNOWN for every configuration absent from its `per_config` map --
#: which is the only way an unmeasured column can stay visible instead of reading as green.
#: `1/xfs` is the native-XFS baseline the 2x performance ceiling is measured against.
CONFIGS = [
    "1/xfs",
    "1/caw", "2/caw", "4/caw", "8/caw", "16/caw", "32/caw",
    "1/tcp", "2/tcp", "4/tcp", "8/tcp", "16/tcp", "32/tcp",
]

TRANSPORTS = ("xfs", "caw", "cawd", "cawp", "tcp")

#: For `lift_config` only: what a leading bare `2 tcp` must not be mistaken for.
SUBCOMMANDS = ("show", "add", "update", "remove",
               "pending", "executing", "finalize", "rows")
VALUE_FLAGS = ("--at", "--build")


def flat(value, width: int | None = None) -> str:
    text = " ".join(str(value).split())
    return text[:width - 1] + "…" if width and len(text) > width else text


def wrap(text, width: int, indent: str) -> str:
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


class Paint:
    def __init__(self, on: bool):
        self.on = on

    def __call__(self, text, code) -> str:
        return f"\033[{code}m{text}\033[0m" if self.on else str(text)


def status_of(entry: dict) -> str:
    return str(entry.get("status", "UNKNOWN")).upper().strip()


def parse_at(text: str) -> str:
    """`2/tcp` -- the same notation the ledger, the harness and the run keys already use.

    A column is one exact key, so unlike the defect queue this needs the transport: `2` alone
    names five different columns and picking one of them silently is how a tcp green gets read
    as a caw one.
    """
    match = re.fullmatch(r"\s*(\d+)\s*(?:/\s*([A-Za-z]+))?\s*", str(text))
    if not match:
        sys.exit(f"criteria: wanted NODES/TRANSPORT such as 2/tcp, not {text!r}")
    nodes = int(match.group(1))
    if nodes < 1:
        sys.exit("criteria: node count must be at least 1")
    if not match.group(2):
        here = [c for c in CONFIGS if c.startswith("%d/" % nodes)]
        sys.exit("criteria: name the transport too — a cell is one exact configuration. "
                 "At %d nodes: %s" % (nodes, ", ".join(here) if here else "none declared"))
    dlm = match.group(2).lower()
    if dlm not in TRANSPORTS:
        sys.exit(f"criteria: transport {dlm!r}; expected one of {list(TRANSPORTS)}")
    return "%d/%s" % (nodes, dlm)


def lift_config(argv: list) -> list:
    """Accept `criteria.py 2 tcp` and `criteria.py 2/tcp`, the way `showstat.sh 2 tcp` always has.

    The leading argument is a configuration only when it starts with digits, so it can never
    shadow `show`, `add`, `update` or `remove`.
    """
    rest, skip = list(argv[1:]), False
    for index, token in enumerate(rest):
        if skip:
            skip = False
            continue
        if token in SUBCOMMANDS:
            break
        if token.startswith("-"):
            #: A flag that takes a value would otherwise have its value read as a node count.
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


def load() -> dict:
    if not CRITERIA.is_file():
        return {"criteria": []}
    try:
        with CRITERIA.open() as handle:
            data = json.load(handle)
    except ValueError as exc:
        raise SystemExit(f"criteria: {CRITERIA} is not valid JSON: {exc}")
    data.setdefault("criteria", [])
    return data


def save(data: dict) -> None:
    """Atomically, because a half-written board is worse than a stale one."""
    CRITERIA.parent.mkdir(parents=True, exist_ok=True)
    temporary = CRITERIA.with_suffix(".json.tmp")
    with temporary.open("w") as handle:
        json.dump(data, handle, indent=2)
        handle.write("\n")
    os.replace(temporary, CRITERIA)


def find(data: dict, wanted: str) -> dict:
    wanted = wanted.strip()
    for entry in data["criteria"]:
        if str(entry.get("id", "")) == wanted:
            return entry
    low = wanted.lower()
    hits = [e for e in data["criteria"] if low in str(e.get("id", "")).lower()]
    if len(hits) == 1:
        return hits[0]
    if not hits:
        sys.exit(f"criteria: nothing matches {wanted!r}")
    sys.exit("criteria: %r matches %d:\n  %s"
             % (wanted, len(hits), "\n  ".join(str(e["id"]) for e in hits)))


def cell_of(entry: dict, config: str) -> dict:
    return (entry.get("per_config") or {}).get(config) or {}


def stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def push_history(cell: dict) -> None:
    """Move the outgoing verdict onto the cell's bounded history BEFORE it is overwritten.

    A cell that holds only its latest result goes green the moment a run gets lucky. Measured:
    `dirent_durability` failed once with durable_loss=3 and then passed 18 consecutive times, and
    the board showed nothing but the last pass. For a defect that reproduces one run in ten that
    makes a green cell meaningless.

    The flake rule reads this history, so a write that does not push is a write that erases the
    only evidence an intermittent defect leaves. A PENDING marker is not a verdict and is never
    pushed -- otherwise every run would fill the window with its own bookkeeping.
    """
    previous = str(cell.get("status", "")).upper().strip()
    if previous in ("", "PENDING"):
        return
    outgoing = {
        "status": cell.get("status"),
        "iso": cell.get("iso") or cell.get("recorded") or "",
        "measured": cell.get("measured", ""),
        #: `reason` names which check failed. The history push used to drop it, and the moment the
        #: next run overwrote the cell that evidence was gone -- which is why one defect sat
        #: "UNROOTED: which check failed is not yet captured" when the answer had been written
        #: down and then discarded.
        "reason": str(cell.get("reason") or "")[:400],
    }
    cell["history"] = ([outgoing] + list(cell.get("history") or []))[:HISTORY_DEPTH]


def write_cell(entry: dict, config: str, status: str, measured: str = "",
               reason: str = "", elapsed_s=None, build: str = "") -> dict:
    """Replace one configuration's cell, preserving its history."""
    cell = entry.setdefault("per_config", {}).setdefault(config, {})
    push_history(cell)
    history = cell.get("history") or []
    cell.clear()
    cell["status"] = status
    cell["measured"] = measured
    cell["reason"] = reason
    cell["iso"] = stamp()
    cell["recorded"] = date.today().isoformat()
    if elapsed_s is not None:
        cell["elapsed_s"] = elapsed_s
    if build:
        cell["build"] = build
    if history:
        cell["history"] = history
    return cell


def flake_count(entry: dict, config: str) -> tuple:
    """(genuine failures, runs considered) over the recent window for one cell.

    Genuine means the test detected a fault on a formed cluster: a recorded failure whose reason
    is not rig-formation noise. The current run counts alongside its history, so a cell that just
    failed for a real reason is not laundered by having no history yet.
    """
    if str(entry.get("id", "")) in NEVER_FLAKE:
        return 0, 0
    cell = cell_of(entry, config)
    if not cell:
        return 0, 0
    runs = [cell] + list(cell.get("history") or [])
    runs = runs[:FLAKE_WINDOW]
    #: FAIL only. ABORTED means the run died mid-test and the result is UNKNOWN -- counting it
    #: would make "we never found out" indistinguishable from "the test detected a fault", which
    #: is the same conflation the rig-noise filter exists to prevent.
    genuine = sum(1 for r in runs
                  if str(r.get("status", "")).upper().strip() == "FAIL"
                  and not RIG_NOISE.search(str(r.get("reason", ""))))
    return genuine, len(runs)


def applies(entry: dict, config: str) -> bool:
    """Is this criterion even runnable in that configuration?

    A single-node tool check is not a pending 2-node result and a CAW-only criterion is not an
    unmeasured TCP column: printing them as UNKNOWN pads the board with rows nothing will ever
    fill, and burying the genuinely unmeasured ones among them is how an empty column stops being
    noticed.
    """
    match = re.fullmatch(r"(\d+)/([A-Za-z]+)", config)
    if not match:
        return True
    nodes, dlm = int(match.group(1)), match.group(2).lower()
    wants = str(entry.get("transport", "any")).lower()
    if wants not in ("any", "") and wants != dlm:
        return False
    if nodes < int(entry.get("min_nodes", 1) or 1):
        return False
    top = int(entry.get("max_nodes", 0) or 0)
    return top == 0 or nodes <= top


def cell_status(entry: dict, config: str, build: str = "") -> str:
    """One configuration's verdict, with staleness and flakiness applied.

    A cell earned on a different build is STALE, not PASS. The build that produced a green is the
    only thing that ties it to the code being asked about, and a board that reprints it against a
    newer module is asserting something nobody measured.

    A cell that passes now but failed for a real reason inside the window is FLAKY, which is not
    green. `fence_during_write` at 2/tcp passed its last run with 6 genuine failures behind it in
    11; a board that called that PASS is the reason this rule exists.
    """
    cell = cell_of(entry, config)
    if not cell:
        return "UNKNOWN"
    status = str(cell.get("status", "UNKNOWN")).upper().strip().replace("_", " ")
    if build and status in GREEN and cell.get("build") and cell["build"] != build:
        return "STALE"
    if status in GREEN and flake_count(entry, config)[0] > 0:
        return "FLAKY"
    return status


def roll_up(entry: dict, build: str = "") -> str:
    """PASS only when every declared configuration has one. Anything else is PARTIAL at best."""
    marks = [cell_status(entry, config, build)
             for config in CONFIGS if applies(entry, config)]
    if not marks:
        return "UNKNOWN"
    if all(mark in GREEN for mark in marks):
        return "PASS"
    if any(mark in ("FAIL", "BLOCKED", "ABORTED") for mark in marks):
        return "FAIL"
    if any(mark in GREEN or mark == "FLAKY" for mark in marks):
        return "PARTIAL"
    return "UNKNOWN"


def show_one(entry: dict, paint: Paint, build: str) -> int:
    print(paint(entry.get("id", "?"), "1"))
    status = roll_up(entry, build)
    print("  %-12s %s" % ("status", paint(status, MARK.get(status, "33"))))
    for key in ("phase", "requirement", "detector", "budget_s", "source", "why", "invariant"):
        if entry.get(key):
            print("  %-12s %s" % (key, wrap(entry[key], 92, " " * 15)))
    runnable = [c for c in CONFIGS if applies(entry, c)]
    print("  %-12s" % "per config")
    for config in runnable:
        cell = cell_of(entry, config)
        mark = cell_status(entry, config, build)
        detail = flat(cell.get("measured", ""), 52)
        elapsed = cell.get("elapsed_s")
        if elapsed is not None and entry.get("budget_s"):
            detail = "%ss/%ss  %s" % (elapsed, entry["budget_s"], detail)
        bad, seen = flake_count(entry, config)
        if bad:
            detail = "%s  [%d genuine FAIL(s) in last %d runs]" % (detail, bad, seen)
        print("    %-10s %s  %s" % (config, paint("%-8s" % mark, MARK.get(mark, "33")), detail))
    skipped = [c for c in CONFIGS if c not in runnable]
    if skipped:
        print("    %-10s not runnable here: %s" % ("", ", ".join(skipped)))
    return 0


def board(criteria: list, paint: Paint, verbose: bool, at: str, build: str) -> int:
    if not criteria:
        print("no criteria. Nothing has been said about what 'done' means.")
        return 0

    width_id = max([9] + [len(str(x.get("id", "?"))) for x in criteria])
    width_status = 8

    if at:
        criteria = [c for c in criteria if applies(c, at)]
        if not criteria:
            print("no criterion is runnable at %s." % at)
            return 0

    scope = at or "every configuration"
    print("=== CRITERIA — what MXFS MUST ACHIEVE — %s ===" % scope)
    print("%-3s | %-*s | %-*s | %-10s | %s" %
          ("#", width_id, "CRITERION", width_status, "STATUS", "BUDGET", "MEASURED"))
    print("%s-+-%s-+-%s-+-%s-+-%s" %
          ("-" * 3, "-" * width_id, "-" * width_status, "-" * 10, "-" * 40))

    tally: dict[str, int] = {}
    last_phase = None
    for number, entry in enumerate(criteria, 1):
        if at:
            status = cell_status(entry, at, build)
            cell = cell_of(entry, at)
            measured, elapsed = cell.get("measured", ""), cell.get("elapsed_s")
            bad, seen = flake_count(entry, at)
            if bad:
                measured = "%s  [%d genuine FAIL(s) in last %d runs]" % (measured, bad, seen)
        else:
            status = roll_up(entry, build)
            done = sum(1 for c in CONFIGS if cell_status(entry, c, build) in GREEN)
            measured, elapsed = "%d of %d configurations" % (done, len(CONFIGS)), None
        tally[status] = tally.get(status, 0) + 1

        phase = entry.get("phase")
        if verbose and phase and phase != last_phase:
            print(paint(f"\n  -- {phase} --", "1"))
            last_phase = phase
        budget = entry.get("budget_s")
        cost = "%s/%ss" % (elapsed, budget) if elapsed is not None and budget else (
            "%ss" % budget if budget else "—")
        print("%-3d | %s | %s | %-10s | %s" %
              (number, paint("%-*s" % (width_id, entry.get("id", "?")), "1"),
               paint("%-*s" % (width_status, status), MARK.get(status, "33")),
               cost, flat(measured, 56)))
        if verbose:
            print("    %s" % wrap(entry.get("requirement", ""), 96, " " * 4))
            if entry.get("why"):
                print("    %s %s" % (paint("why:", "2"), wrap(entry["why"], 96, " " * 4)))
            print()

    print("-" * (3 + width_id + width_status + 56))
    print("Total: %d — %s" %
          (len(criteria), ", ".join(f"{v} {k}" for k, v in sorted(tally.items()))))

    passing = sum(tally.get(mark, 0) for mark in GREEN)
    unmeasured = tally.get("UNKNOWN", 0) + tally.get("STALE", 0) + tally.get("PARTIAL", 0)
    if passing == len(criteria):
        print(paint("VERDICT: every criterion green%s." % (" for %s" % at if at else ""), "32"))
    else:
        print(paint("VERDICT: %d of %d criteria are not passing. The bar is not met."
                    % (len(criteria) - passing, len(criteria)), "1;31"))
    if unmeasured:
        print(paint("NOTE: %d criterion/criteria are UNMEASURED or STALE, not failed. "
                    "Unmeasured is not a pass — nothing has been proved about them."
                    % unmeasured, "33"))
    return 0


def detector_script(detector: str) -> str:
    """
    The repo file a detector runs, or empty when it does not name one.

    A detector is a COMMAND, and only some of them are a file in this tree: a detector may be a
    tool invocation with nothing here to check. What can be checked is the ones that name a path,
    and those are the ones that rot.
    """
    for word in str(detector).split():
        if word.endswith(".py") or word.endswith(".sh") or word.endswith(".c"):
            return word
    return ""


def cmd_gaps(criteria: list, paint: Paint, build: str) -> int:
    """
    Every criterion nobody can currently measure, and every configuration nobody has measured.

    NAMING A DETECTOR IS NOT HAVING ONE, and a `--gaps` that only asks whether the field is filled
    in will print "every criterion has a detector" while a named file has never existed. A named
    detector that is not there is worse than a blank field, because a blank field is visible.

    THE EMPTY COLUMNS ARE A GAP TOO. A criterion with a real detector that has never been run on a
    configuration proves nothing about that configuration, and that is exactly the hole a board
    reading green is hiding.
    """
    root = ROOT
    missing, absent, unrun = [], [], []
    for entry in criteria:
        detector = str(entry.get("detector", "")).strip()
        if not detector:
            missing.append((entry, "no detector at all"))
        else:
            script = detector_script(detector)
            if script and not (root / script).exists():
                absent.append((entry, f"names {script}, which does not exist"))
        runnable = [c for c in CONFIGS if applies(entry, c)]
        never = [c for c in runnable if not cell_of(entry, c)]
        if never:
            unrun.append((entry, "never run on %d of %d runnable configurations: %s"
                          % (len(never), len(runnable), ", ".join(never))))
    gaps = missing + absent + unrun
    if not gaps:
        print("every criterion has a detector that exists, and every configuration has a cell.")
        return 0
    print(f"{len(gaps)} gap(s) — a requirement nobody can measure is a wish, and a "
          f"configuration nobody has measured is not a pass:\n")
    for entry, why in gaps:
        print(paint(entry.get("id", "?"), "1"), "—", why)
        print("  %s" % wrap(entry.get("requirement", ""), 92, " " * 2))
        print()
    return 0


def cmd_add(data: dict, args) -> int:
    taken = {str(x.get("id", "")) for x in data["criteria"]}
    if args.id in taken:
        sys.exit(f"criteria: {args.id} already exists")
    entry = {"id": args.id,
             "requirement": args.requirement,
             "detector": args.detector,
             "per_config": {}}
    if args.budget_s is not None:
        if args.budget_s <= 0:
            sys.exit("criteria: -b/--budget-s is a time budget in seconds; must be positive")
        entry["budget_s"] = args.budget_s
    for key, value in (("phase", args.phase), ("why", args.why), ("source", args.source),
                       ("coord", args.coord), ("min_nodes", args.min_nodes),
                       ("max_nodes", args.max_nodes)):
        if value:
            entry[key] = value
    data["criteria"].append(entry)
    save(data)
    if args.budget_s is None:
        print("NOTE: no budget. A criterion with no time budget cannot fail on time, which is "
              "how a workload 30x slower than native reads as a pass. Set one with -b.")
    print(f"added {entry['id']}")
    return 0


def cmd_move(data: dict, args) -> int:
    """Put a criterion immediately before (or after) another on the board.

    The board's list order IS the dispatch order: run.sh runs the rows in the order `rows` emits
    them, and `add` appends. A row whose evidence another row consumes (alloc_witness seals the
    coverage witness chk_clean refuses to audit without, under the same run id) has to sit
    immediately before its consumer, and appending it put it after — the audit ran first, on a
    fresh format, and reported no witness for its run.
    """
    entry = find(data, args.id)
    anchor = find(data, args.before or args.after)
    if entry is anchor:
        sys.exit(f"criteria: {args.id} cannot be moved relative to itself")
    rest = [x for x in data["criteria"] if x is not entry]
    at = rest.index(anchor) + (0 if args.before else 1)
    rest.insert(at, entry)
    data["criteria"] = rest
    save(data)
    print(f"moved {entry['id']} {'before' if args.before else 'after'} {anchor['id']}")
    return 0


def cmd_update(data: dict, args) -> int:
    entry = find(data, args.id)

    changed = []
    for field, value in (("requirement", args.requirement), ("detector", args.detector),
                         ("why", args.why), ("budget_s", args.budget_s),
                         ("coord", args.coord), ("min_nodes", args.min_nodes),
                         ("max_nodes", args.max_nodes)):
        if value:
            entry[field] = value
            changed.append(field)

    if args.at:
        #: A CELL IS ONE CONFIGURATION'S MEASUREMENT. Recording it against the criterion as a whole
        #: is what let a 32/caw green stand in for 2/tcp, so a measurement without --at is refused
        #: rather than written somewhere it will be misread.
        config = parse_at(args.at)
        status = args.status.upper().strip() if args.status else None
        if status and status not in STATUSES:
            sys.exit(f"criteria: status {status!r}; expected one of {list(STATUSES)}")

        reason = args.reason or ""
        overrun = ""
        if args.elapsed_s is not None:
            budget = entry.get("budget_s")
            #: A budget is a performance assertion, so an overrun is a FAILURE and not a slow
            #: pass -- even with zero errors, even when the caller says PASS. The board cannot be
            #: the place where "it finished eventually" becomes green.
            #:
            #: The one exception is a CALIBRATION run, which exists to establish a budget that
            #: does not exist yet: there is nothing to enforce, so the cell is tagged as
            #: unenforced measurement data rather than being scored against a number nobody set.
            if args.calibrate:
                reason = ("[CALIBRATION: budget not enforced, elapsed=%ss]%s%s"
                          % (args.elapsed_s, " " if reason else "", reason))
            elif budget and args.elapsed_s > budget and status in GREEN:
                status = "FAIL"
                reason = ("budget exceeded: elapsed=%ss > budget=%ss (functional checks passed)%s%s"
                          % (args.elapsed_s, budget, "; " if reason else "", reason))
                overrun = ("  OVERRUN: %ss against a %ss budget — recorded FAIL, not PASS"
                           % (args.elapsed_s, budget))

        previous = cell_of(entry, config)
        cell = write_cell(entry, config,
                          status or str(previous.get("status", "UNKNOWN")),
                          args.measured if args.measured is not None else previous.get("measured", ""),
                          reason,
                          args.elapsed_s,
                          args.build or "")
        save(data)
        print("updated %s [%s] -> %s (%s overall)"
              % (entry["id"], config, cell.get("status", "UNKNOWN"), roll_up(entry)))
        if overrun:
            print(overrun)
        if not args.build:
            print("NOTE: no --build. A cell with no build identity cannot go stale, so it will "
                  "keep reading green against every future module.")
        return 0

    if args.status or args.measured or args.elapsed_s is not None or args.build:
        sys.exit("criteria: a measurement needs --at NODES/TRANSPORT saying which configuration "
                 "it was measured on; a status with no configuration is how one column's green "
                 "gets read as the whole matrix")
    if not changed:
        sys.exit("criteria: update needs at least one field to change")
    entry["recorded"] = date.today().isoformat()
    save(data)
    print(f"updated {entry['id']}: {', '.join(changed)}")
    return 0


#: THE PENDING LIFECYCLE. These three exist so the harness never writes this file itself.
#:
#: A board that leaves last run's PASS on screen while a run is in flight is reporting a result
#: that is not being measured. So a run marks everything it intends to run PENDING first, stamps
#: the one test actually in flight, and converts whatever markers survive when it exits.
#:
#: The two survivors mean different things and must not be conflated. A test that was EXECUTING
#: when the run died may have wedged the node and must not read green. A test the run never
#: reached says nothing whatever about the filesystem -- scoring it FAIL painted boards red with
#: tests that never executed, which destroys the board's only job of being believable.
def cmd_pending(data: dict, args) -> int:
    config = parse_at(args.at)
    marked = []
    for wanted in args.id:
        entry = find(data, wanted)
        write_cell(entry, config, "PENDING", "", "running %s" % args.run_id)
        marked.append(str(entry["id"]))
    save(data)
    print("marked %d PENDING for %s: %s" % (len(marked), config, " ".join(marked)))
    return 0


def cmd_executing(data: dict, args) -> int:
    config = parse_at(args.at)
    entry = find(data, args.id)
    cell = entry.setdefault("per_config", {}).setdefault(config, {})
    if str(cell.get("status", "")).upper().strip() != "PENDING":
        #: Not an error: a forced single-test run has no marker to stamp.
        return 0
    cell["reason"] = "executing %s" % args.run_id
    cell["iso"] = stamp()
    save(data)
    return 0


def cmd_finalize(data: dict, args) -> int:
    run = args.run_id or ""
    converted = []
    for entry in data["criteria"]:
        for config, cell in (entry.get("per_config") or {}).items():
            if str(cell.get("status", "")).upper().strip() != "PENDING":
                continue
            reason = str(cell.get("reason") or "")
            if run:
                inflight, unreached = reason == "executing " + run, reason == "running " + run
            else:
                #: No run id: every pre-existing marker belongs to a run that is already dead,
                #: because the harness serialises runs behind a lock. Heal them all.
                inflight = reason.startswith("executing ")
                unreached = reason.startswith("running ")
            if inflight:
                write_cell(entry, config, "ABORTED", "",
                           "run died while this test was executing — result unknown, re-run it")
            elif unreached:
                write_cell(entry, config, "NOT RUN", "",
                           "sweep ended before reaching this test — not a result")
            else:
                continue
            converted.append("%s[%s]" % (entry["id"], config))
    if converted:
        save(data)
        print("finalized %d marker(s): %s" % (len(converted), " ".join(converted)))
    return 0


def cmd_rows(data: dict, args) -> int:
    """The matrix as TSV, for the harness dispatch loop.

    Eight columns: phase, transport, id, coord, min_nodes, max_nodes, budget_s, budget_scale.
    The harness reads this instead of parsing the board itself, so `criteria.py` stays the only
    thing that knows this file's shape.
    """
    for entry in data["criteria"]:
        print("\t".join(str(x) for x in (
            entry.get("phase", ""),
            entry.get("transport", "any"),
            entry.get("id", ""),
            entry.get("coord", "none"),
            int(entry.get("min_nodes", 1) or 1),
            int(entry.get("max_nodes", 0) or 0),
            int(entry.get("budget_s", 300) or 300),
            entry.get("budget_scale", "flat"),
        )))
    return 0


def cmd_remove(data: dict, args) -> int:
    """Only for a criterion that is no longer something we must achieve.

    NOT FOR ONE THAT NOW PASSES. A criterion is permanent and can regress; taking a green one off
    the board is how a regression becomes invisible. That is the opposite of the defect queue,
    where a fixed entry is removed precisely because it is no longer work.
    """
    entry = find(data, args.id)
    was = roll_up(entry)
    data["criteria"] = [x for x in data["criteria"] if x is not entry]
    save(data)
    print(f"removed {entry['id']}")
    if was in GREEN:
        print("\nNOTE: that criterion was PASSING. If it is still something MXFS must do, "
              "put it back — a green taken off the board cannot regress visibly.")
    print("\nThis changes what 'done' means. It belongs in CHANGELOG.md:\n")
    print(f"- **Criterion {entry['id']} withdrawn** — {args.why}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="add each criterion's requirement and why it exists")
    parser.add_argument("--at", metavar="NODES/DLM",
                        help="one release configuration's column, e.g. 2/tcp. "
                             "May also be given bare: `criteria.py 2 tcp`")
    parser.add_argument("--build", default="",
                        help="the module srcversion under test; a cell earned on another "
                             "build reads STALE instead of PASS")
    parser.add_argument("--gaps", action="store_true",
                        help="criteria nobody can measure, and configurations nobody has")
    parser.add_argument("--no-colour", action="store_true")

    subs = parser.add_subparsers(dest="command")

    show = subs.add_parser("show", help="one criterion in full")
    show.add_argument("id")
    show.add_argument("--build", help="module srcversion under test; a cell earned on another "
                                      "build reads STALE instead of PASS")

    add = subs.add_parser("add", help="a new thing MXFS must achieve")
    add.add_argument("-i", "--id", required=True)
    add.add_argument("-r", "--requirement", required=True, help="what must be true")
    add.add_argument("-d", "--detector", required=True,
                     help="how it is measured. Without one this is a wish, not a criterion")
    add.add_argument("-b", "--budget-s", type=int, dest="budget_s",
                     help="time budget in seconds. Derive it from what the operation SHOULD "
                          "take, never from what fits the tool cap")
    add.add_argument("-p", "--phase")
    add.add_argument("--why", help="why this matters")
    add.add_argument("--source", help="where the requirement came from")
    #: How run.sh dispatches the row (`rows` prints these): coord none runs the
    #: script on one node, barrier/ordered/fault on every node with a rank and
    #: a coordination prefix, host on this host. A clustered row added without
    #: them ran on one node, waited at its first barrier for a rank that was
    #: never launched, and recorded its own ABORT as a FAIL about MXFS.
    add.add_argument("--coord", choices=("none", "barrier", "ordered", "fault", "host"),
                     help="dispatch class: none (one node) | barrier/ordered/fault (every "
                          "node, ranked, coordinated) | host (this host)")
    add.add_argument("--min-nodes", type=int, dest="min_nodes",
                     help="the smallest node count the row is meaningful at (SKIPPED below it)")
    add.add_argument("--max-nodes", type=int, dest="max_nodes",
                     help="the largest node count the row runs at (0 = no cap)")

    update = subs.add_parser("update", help="record a measurement")
    update.add_argument("id")
    update.add_argument("--at", metavar="NODES/DLM",
                        help="the configuration this was measured on, e.g. 2/tcp")
    update.add_argument("-s", "--status", help=f"one of {list(STATUSES)}")
    update.add_argument("-m", "--measured", help="what the detector said")
    #: No short flag: `-r` is already `--requirement` on this subcommand, and silently taking it
    #: over would make an old invocation write a failure reason into the requirement text.
    update.add_argument("--reason", help="WHICH check failed — the flake rule reads this "
                                         "to tell a real fault from the rig not forming")
    update.add_argument("--calibrate", action="store_true",
                        help="measurement run to establish a budget that does not exist yet: "
                             "record the elapsed time without enforcing a budget against it")
    update.add_argument("-e", "--elapsed-s", type=int, dest="elapsed_s",
                        help="wall seconds. Over the budget records FAIL, not PASS")
    update.add_argument("--build", help="module srcversion this cell was earned on")
    #: A criterion is permanent; its WORDING gets more exact as the bar is pinned down, which is
    #: what these are for. Sharpening a requirement is not the same act as `remove`, which means
    #: "no longer something we must achieve" and throws the provenance away.
    update.add_argument("-r", "--requirement", help="restate what must be true")
    update.add_argument("-d", "--detector", help="restate how it is measured")
    update.add_argument("-b", "--budget-s", type=int, dest="budget_s",
                        help="restate the time budget. Widening one to make a cell green is "
                             "the edit this board exists to make visible")
    update.add_argument("--why", dest="why", help="restate why it matters")
    update.add_argument("--coord", choices=("none", "barrier", "ordered", "fault", "host"),
                        help="restate the dispatch class (see add)")
    update.add_argument("--min-nodes", type=int, dest="min_nodes")
    update.add_argument("--max-nodes", type=int, dest="max_nodes")

    remove = subs.add_parser("remove", help="no longer something we must achieve")
    remove.add_argument("id")
    remove.add_argument("--why", required=True, help="why this is no longer required")

    move = subs.add_parser("move", help="reorder: the board's order is the dispatch order")
    move.add_argument("id")
    where = move.add_mutually_exclusive_group(required=True)
    where.add_argument("--before", help="the criterion this one must run immediately before")
    where.add_argument("--after", help="the criterion this one must run immediately after")

    pending = subs.add_parser("pending", help="mark criteria as in-flight for a run")
    pending.add_argument("id", nargs="+")
    pending.add_argument("--at", metavar="NODES/DLM", required=True)
    pending.add_argument("--run-id", dest="run_id", required=True)

    executing = subs.add_parser("executing", help="stamp the one criterion actually in flight")
    executing.add_argument("id")
    executing.add_argument("--at", metavar="NODES/DLM", required=True)
    executing.add_argument("--run-id", dest="run_id", required=True)

    finalize = subs.add_parser("finalize", help="convert leftover PENDING markers to a result")
    finalize.add_argument("--run-id", dest="run_id", default="",
                          help="only this run's markers; omit to heal every stale marker")

    subs.add_parser("rows", help="the matrix as TSV, for the harness dispatch loop")

    args = parser.parse_args(lift_config(sys.argv)[1:])
    for absent in ("at", "build", "gaps", "verbose", "budget_s", "requirement",
                   "detector", "why", "status", "measured", "elapsed_s",
                   "reason", "calibrate", "run_id"):
        if not hasattr(args, absent):
            setattr(args, absent, None)
    paint = Paint(not args.no_colour and sys.stdout.isatty()
                  and os.environ.get("TERM", "") not in ("", "dumb"))
    data = load()

    if args.command == "show":
        return show_one(find(data, args.id), paint, args.build or "")
    if args.command == "add":
        return cmd_add(data, args)
    if args.command == "update":
        return cmd_update(data, args)
    if args.command == "remove":
        return cmd_remove(data, args)
    if args.command == "move":
        return cmd_move(data, args)
    if args.command == "pending":
        return cmd_pending(data, args)
    if args.command == "executing":
        return cmd_executing(data, args)
    if args.command == "finalize":
        return cmd_finalize(data, args)
    if args.command == "rows":
        return cmd_rows(data, args)
    if args.gaps:
        return cmd_gaps(data["criteria"], paint, args.build or "")
    return board(data["criteria"], paint, args.verbose,
                 parse_at(args.at) if args.at else "", args.build or "")


if __name__ == "__main__":
    sys.exit(main())

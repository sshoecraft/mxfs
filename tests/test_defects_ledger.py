#!/usr/bin/env python3
"""Regression tests for the defect ledger's writer: locking, atomicity, the release bar, exit codes.

Every test runs against a COPY of the ledger in a temporary tree, never `data/defects.json`. The
tool derives its paths from `__file__`, so a sandbox is just `<tmp>/tools/defects.py` plus
`<tmp>/data/defects.json` -- which also means a test that forgot to sandbox would write the real
queue, so the sandbox path is asserted before anything mutates.

What each test pins, and why it is here rather than left to review:

  lost update   Two concurrent `remove`s used to each read the same snapshot and each write their
                own, so the later write resurrected the record the earlier one took out -- both
                reporting success, in a file carrying no dates. Nothing afterwards showed it.
  torn read     A reader hitting the ~6 ms rewrite window saw a truncated document.
  release bar   `--release` gates on `impact`, which for a while no subcommand could write, so the
                blocking set could not be adjudicated through the tool at all.
  exit code     Every list path exited 0 whether it printed 16 records or none, so no script could
                tell "clear" from "still blocked" without parsing prose.

Run: tests/test_defects_ledger.py        (add -v for per-case output)
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REAL_LEDGER = ROOT / "data" / "defects.json"
REAL_TOOL = ROOT / "tools" / "defects.py"

VERBOSE = "-v" in sys.argv[1:]
failures = []


def note(message):
    if VERBOSE:
        print("    %s" % message)


def sandbox(tmp):
    """A working copy of the tool and the real ledger, with the real paths proven unreachable."""
    (tmp / "tools").mkdir(parents=True, exist_ok=True)
    (tmp / "data").mkdir(parents=True, exist_ok=True)
    tool = tmp / "tools" / "defects.py"
    ledger = tmp / "data" / "defects.json"
    shutil.copy2(REAL_TOOL, tool)
    shutil.copy2(REAL_LEDGER, ledger)
    assert tool.resolve() != REAL_TOOL.resolve(), "sandbox tool is the real tool"
    assert ledger.resolve() != REAL_LEDGER.resolve(), "sandbox ledger is the real ledger"
    return tool, ledger


def run(tool, *argv, **kwargs):
    return subprocess.run([sys.executable, str(tool)] + [str(a) for a in argv],
                          capture_output=True, text=True, **kwargs)


def ids_of(ledger):
    with ledger.open() as handle:
        return [e["id"] for e in json.load(handle)["defects"]]


def case(name):
    """Decorator-free registry: each test is a function called by main() and reports one line."""
    def record(ok, detail=""):
        print("%-6s %s%s" % ("ok" if ok else "FAIL", name, "" if ok else "  -- " + detail))
        if not ok:
            failures.append(name)
    return record


def test_concurrent_removes_both_persist():
    report = case("concurrent removes: both records stay removed")
    with tempfile.TemporaryDirectory() as raw:
        tmp = Path(raw)
        tool, ledger = sandbox(tmp)
        before = ids_of(ledger)
        if len(before) < 2:
            report(False, "ledger copy has fewer than 2 records")
            return
        lost = []
        trials = 20
        for trial in range(trials):
            shutil.copy2(REAL_LEDGER, ledger)
            first, second = before[0], before[1]
            procs = [
                subprocess.Popen([sys.executable, str(tool), "remove", first,
                                  "--why", "test"], stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL),
                subprocess.Popen([sys.executable, str(tool), "remove", second,
                                  "--why", "test"], stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL),
            ]
            for proc in procs:
                proc.wait()
            after = ids_of(ledger)
            back = [i for i in (first, second) if i in after]
            if back:
                lost.append((trial, back))
        note("%d trials, %d with a resurrected record" % (trials, len(lost)))
        report(not lost, "resurrected on %d/%d trials: %s" % (len(lost), trials, lost[:3]))


def test_lock_actually_excludes():
    report = case("lock excludes a second writer while held")
    import fcntl
    with tempfile.TemporaryDirectory() as raw:
        tmp = Path(raw)
        tool, ledger = sandbox(tmp)
        victim = ids_of(ledger)[0]
        held = (tmp / "data" / ".defects.lock").open("w")
        fcntl.flock(held.fileno(), fcntl.LOCK_EX)
        proc = subprocess.Popen([sys.executable, str(tool), "remove", victim, "--why", "test"],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        #: Generous next to a ~6 ms write: if the writer were unlocked it would have finished many
        #: times over, so still-running here means the lock is doing its job.
        time.sleep(0.4)
        blocked = proc.poll() is None
        still_present = victim in ids_of(ledger)
        note("blocked=%s record_still_present=%s" % (blocked, still_present))
        fcntl.flock(held.fileno(), fcntl.LOCK_UN)
        held.close()
        proc.wait(timeout=30)
        gone_after = victim not in ids_of(ledger)
        note("completed_after_release=%s" % gone_after)
        report(blocked and still_present and gone_after,
               "blocked=%s present_while_held=%s removed_after_release=%s"
               % (blocked, still_present, gone_after))


def test_save_is_atomic_no_torn_read():
    report = case("no torn read: a reader never sees a partial ledger")
    with tempfile.TemporaryDirectory() as raw:
        tmp = Path(raw)
        tool, ledger = sandbox(tmp)
        victims = ids_of(ledger)[:12]
        torn = 0
        reads = 0
        procs = []
        for victim in victims:
            procs.append(subprocess.Popen(
                [sys.executable, str(tool), "remove", victim, "--why", "test"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        deadline = time.monotonic() + 6
        while any(p.poll() is None for p in procs) and time.monotonic() < deadline:
            try:
                with ledger.open() as handle:
                    json.load(handle)
                reads += 1
            except ValueError:
                torn += 1
            except OSError:
                pass
        for proc in procs:
            proc.wait(timeout=30)
        note("%d clean reads, %d torn" % (reads, torn))
        report(torn == 0 and reads > 0, "%d torn reads out of %d" % (torn, reads + torn))


def test_impact_requires_a_reason():
    report = case("release bar: -I without --impact-why is refused")
    with tempfile.TemporaryDirectory() as raw:
        tmp = Path(raw)
        tool, ledger = sandbox(tmp)
        victim = ids_of(ledger)[0]
        bare = run(tool, "update", victim, "-I", "noblock")
        withwhy = run(tool, "update", victim, "-I", "noblock",
                      "--impact-why", "measured: no corruption, no node loss over 40 laps")
        why_alone = run(tool, "update", ids_of(ledger)[1], "--impact-why", "no bar set yet")
        note("bare rc=%d withwhy rc=%d why_alone rc=%d"
             % (bare.returncode, withwhy.returncode, why_alone.returncode))
        report(bare.returncode != 0 and withwhy.returncode == 0 and why_alone.returncode != 0,
               "bare=%d (want !=0) withwhy=%d (want 0) why_alone=%d (want !=0)"
               % (bare.returncode, withwhy.returncode, why_alone.returncode))


def test_impact_noblock_leaves_the_release_set():
    report = case("release bar: noblock drops a record from --release, and only from --release")
    with tempfile.TemporaryDirectory() as raw:
        tmp = Path(raw)
        tool, ledger = sandbox(tmp)
        first = json.loads(run(tool, "2", "tcp", "--release", "--json").stdout)["defects"]
        if not first:
            report(False, "the 2/tcp release set is already empty in this copy")
            return
        victim = first[0]["id"]
        setbar = run(tool, "update", victim, "-I", "noblock",
                     "--impact-why", "measured: neither corrupts nor destabilises")
        after = json.loads(run(tool, "2", "tcp", "--release", "--json").stdout)["defects"]
        without = json.loads(run(tool, "2", "tcp", "--json").stdout)["defects"]
        left_release = victim not in [e["id"] for e in after]
        still_open = victim in [e["id"] for e in without]
        note("release %d -> %d, still in plain 2/tcp: %s"
             % (len(first), len(after), still_open))
        report(setbar.returncode == 0 and left_release and still_open
               and len(after) == len(first) - 1,
               "rc=%d left_release=%s still_open=%s %d->%d"
               % (setbar.returncode, left_release, still_open, len(first), len(after)))


def test_gate_exit_code():
    report = case("--gate: exit 1 while blocked, 0 when clear, 0 without the flag")
    with tempfile.TemporaryDirectory() as raw:
        tmp = Path(raw)
        tool, ledger = sandbox(tmp)
        blocked = run(tool, "2", "tcp", "--release", "--gate")
        blocked_json = run(tool, "2", "tcp", "--release", "--gate", "--json")
        nogate = run(tool, "2", "tcp", "--release")
        #: An empty set MUST exit 0, or the flag says nothing -- and the empty case has to be
        #: proven, not assumed: an earlier version of this test filtered on `1/xfs`, got 5 records
        #: back, and asserted the blocked branch a second time while reporting that it had covered
        #: "clear". A severity no record carries is empty by construction.
        clear = run(tool, "-s", "nosuchseverity", "--release", "--gate")
        clear_ids = json.loads(
            run(tool, "-s", "nosuchseverity", "--release", "--json").stdout)["defects"]
        clear_json = run(tool, "-s", "nosuchseverity", "--release", "--gate", "--json")
        note("blocked rc=%d json rc=%d nogate rc=%d | clear set size %d rc=%d json rc=%d"
             % (blocked.returncode, blocked_json.returncode, nogate.returncode,
                len(clear_ids), clear.returncode, clear_json.returncode))
        if clear_ids:
            report(False, "the 'clear' filter matched %d records, so exit-0-on-empty is untested"
                          % len(clear_ids))
            return
        ok = (blocked.returncode == 1 and blocked_json.returncode == 1
              and nogate.returncode == 0
              and clear.returncode == 0 and clear_json.returncode == 0)
        report(ok, "blocked=%d json=%d nogate=%d clear=%d clear_json=%d"
               % (blocked.returncode, blocked_json.returncode, nogate.returncode,
                  clear.returncode, clear_json.returncode))


def test_real_ledger_untouched():
    report = case("the real data/defects.json was never written by this run")
    stamp = REAL_LEDGER.stat()
    ok = stamp.st_mtime == test_real_ledger_untouched.mtime_at_start
    note("mtime %.6f (start %.6f)" % (stamp.st_mtime,
                                      test_real_ledger_untouched.mtime_at_start))
    report(ok, "mtime moved: %.6f -> %.6f"
           % (test_real_ledger_untouched.mtime_at_start, stamp.st_mtime))


def main():
    if not REAL_LEDGER.is_file():
        sys.exit("no %s to copy" % REAL_LEDGER)
    test_real_ledger_untouched.mtime_at_start = REAL_LEDGER.stat().st_mtime
    print("defect-ledger writer tests (sandboxed copies of %s)" % REAL_LEDGER)
    for test in (test_concurrent_removes_both_persist,
                 test_lock_actually_excludes,
                 test_save_is_atomic_no_torn_read,
                 test_impact_requires_a_reason,
                 test_impact_noblock_leaves_the_release_set,
                 test_gate_exit_code,
                 test_real_ledger_untouched):
        try:
            test()
        except Exception as exc:                      # a crashed test is a failed test
            print("FAIL   %s  -- raised %s: %s" % (test.__name__, type(exc).__name__, exc))
            failures.append(test.__name__)
    print()
    if failures:
        print("%d failed: %s" % (len(failures), ", ".join(failures)))
        return 1
    print("all passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())

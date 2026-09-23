#!/usr/bin/env python3
"""Lint the test-harness corpus for shapes that let a verdict be reported for
work that never happened.

Six independent instances of that failure were found across two sessions, each
capable of closing a defect record on evidence that measured nothing.  Every rule
here is derived from one of them, and each rule names its origin so a reader can
judge the rule against the incident rather than take it on faith.

This is deliberately a SMALL rule set.  A linter with a high false-positive rate
gets suppressed wholesale, and then it protects nothing.  Rules that would fire
on hundreds of benign lines were considered and rejected: an audit of `rc=$?`
capture-without-test, for instance, found 690 occurrences of which the
overwhelming majority are `echo "STAGE <name> rc=$?"` progress logging where the
verdict is computed elsewhere entirely.  Flagging those would bury the four
rules below that actually discriminate.

Usage:
    tools/harness_lint.py                # lint the corpus, exit 1 on findings
    tools/harness_lint.py --baseline     # write the current findings as accepted
    tools/harness_lint.py --new-only     # fail only on findings not in the baseline

The `--new-only` mode is the one to wire into a gate: legacy violations are
reported but do not fail, while a NEW one does.  Burning down the legacy list is
separate work from stopping the bleeding.

Suppress a single line with a comment naming the reason, either trailing on the
line itself or on the line immediately above it:
    # harness-lint: ok - <why this instance is safe>
A bare suppression with no reason is not honoured.
"""
import argparse
import json
import os
import re
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASELINE = os.path.join(REPO, "tests", "criteria", "harness_lint_baseline.json")
SCAN_DIRS = ("tests", "scripts", "tools")
SUPPRESS_RE = re.compile(r"#\s*harness-lint:\s*ok\s*-\s*\S")

RULES = []


def rule(code, why):
    def deco(fn):
        RULES.append((code, why, fn))
        return fn

    return deco


@rule(
    "HL001",
    "implicit selection of verdict evidence: `ls -t`/`ls -dt` piped to head/tail "
    "returns the PREVIOUS run's artifact when this run produced none, so a stale "
    "VERDICT PASS is scored as the current lap's.  A consecutive-streak criterion "
    "can climb on laps that never happened this way.  Pin the artifact before the "
    "step and require it to have changed (see tests/sess480_chain120_ndr_streak_06437.sh).",
)
def hl001(line):
    return bool(re.search(r"ls\s+-[a-z]*t[a-z]*\s.*\|\s*(head|tail)\s+-1", line))


@rule(
    "HL002",
    "unconditional render of a status artifact: showstat.sh renders whatever "
    ".last_run.json points at, so calling it without first proving THIS run "
    "recorded a board prints a previous run's verdict.  Observed printing a board "
    "from the previous DAY, on an older build, one second after run.sh exited 3 on "
    "the run lock.  Pin run_id before, require it to have moved after.",
)
def hl002(line):
    if "showstat.sh" not in line:
        return False
    # A call that already names an explicit run/artifact is fine.
    return not re.search(r"run_id|RUN_ID|--run\b", line)


@rule(
    "HL003",
    "textual tool used as a numeric predicate: `grep -qv '^0$'` means \"some output "
    "line is not exactly 0\" -- true for ANY unexpected line and false for EMPTY "
    "output, which is the opposite of the intended \"the count is non-zero\".  An "
    "ordering gate written this way opened early and the arm measured a peer write "
    "against a holder that did not exist yet.  Test the number as a number.",
)
def hl003(line):
    return bool(re.search(r"grep\s+-[a-z]*q[a-z]*v[a-z]*\s+'\^?0\$?'", line)
                or re.search(r"grep\s+-[a-z]*v[a-z]*q[a-z]*\s+'\^?0\$?'", line))


@rule(
    "HL004",
    "shell variable inside a single-quoted pattern: single quotes prevent "
    "expansion, so the remote grep searches for the LITERAL text (e.g. `slot "
    "$vslot`).  The line being looked for was present in every capture and read as "
    "absent for as long as the assertion existed -- an assertion that could never "
    "pass.  Only flagged when the quoted pattern is NOT inside an enclosing "
    "double-quoted string, which is the common and correct remote-command form.",
)
def hl004(line, in_dquote=False):
    # The dominant idiom in this corpus is a MULTI-LINE remote command string:
    #     ssh_node "$READER" "
    #         if ! mount | grep -q ' on $MXFS_MOUNT type mxfs'; then ...
    #     "
    # There the single quotes are literal characters for the REMOTE grep and
    # $MXFS_MOUNT expands locally before being sent -- correct, and not this
    # defect.  An earlier version of this rule only checked for a double quote
    # on the SAME line, so it flagged tests/criteria/lib.sh:181 and
    # tests/criteria/crash_consistency.sh:80 -- both correct, and both in the
    # board's own criteria scripts, which is the worst possible place to cry
    # wolf.  Tracking double-quote parity across lines fixes exactly that.
    if in_dquote or '"' in line:
        return False
    if not re.search(r"\b(grep|awk|sed)\b", line):
        return False
    for m in re.finditer(r"'([^']*)'", line):
        body = m.group(1)
        # $1/$2 inside awk are field refs, not shell variables.
        if re.search(r"\$[A-Za-z_][A-Za-z0-9_]*", body):
            return True
    return False


def scan():
    findings = []
    for d in SCAN_DIRS:
        base = os.path.join(REPO, d)
        for root, _dirs, files in os.walk(base):
            if "evidence" in root.split(os.sep):
                continue
            for fn in sorted(files):
                if not fn.endswith(".sh"):
                    continue
                path = os.path.join(root, fn)
                rel = os.path.relpath(path, REPO)
                try:
                    with open(path, errors="replace") as fh:
                        lines = fh.read().splitlines()
                except OSError:
                    continue
                in_dq = False
                for n, line in enumerate(lines, 1):
                    was_in_dq = in_dq
                    # Track unescaped double-quote parity across lines so a rule
                    # can tell whether it is looking at text inside an open
                    # multi-line remote command string.
                    if not line.lstrip().startswith("#"):
                        in_dq ^= (len(re.findall(r'(?<!\\)"', line)) % 2 == 1)
                    stripped = line.lstrip()
                    if stripped.startswith("#"):
                        continue
                    # A suppression counts on the offending line OR on the line
                    # immediately above it.  Verdict lines here are often long
                    # pipelines, and forcing the reason onto the same line makes
                    # it unreadable -- which is how suppressions end up reasonless.
                    prev = lines[n - 2] if n >= 2 else ""
                    if SUPPRESS_RE.search(line) or SUPPRESS_RE.search(prev):
                        continue
                    for code, _why, fn_ in RULES:
                        try:
                            hit = fn_(line, was_in_dq)
                        except TypeError:
                            hit = fn_(line)
                        if hit:
                            findings.append(
                                {"code": code, "file": rel, "line": n, "text": line.strip()[:160]}
                            )
    return findings


def key(f):
    return f"{f['code']}:{f['file']}:{f['text']}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--baseline", action="store_true", help="record findings as accepted legacy")
    ap.add_argument("--new-only", action="store_true", help="fail only on findings not in baseline")
    args = ap.parse_args()

    findings = scan()

    if args.baseline:
        os.makedirs(os.path.dirname(BASELINE), exist_ok=True)
        with open(BASELINE, "w") as fh:
            json.dump(sorted(key(f) for f in findings), fh, indent=1)
        print(f"baseline written: {len(findings)} accepted legacy findings -> {BASELINE}")
        return 0

    accepted = set()
    if os.path.exists(BASELINE):
        with open(BASELINE) as fh:
            accepted = set(json.load(fh))

    new = [f for f in findings if key(f) not in accepted]
    shown = new if args.new_only else findings

    by_code = {}
    for f in shown:
        by_code.setdefault(f["code"], []).append(f)

    for code, why, _ in RULES:
        hits = by_code.get(code, [])
        if not hits:
            continue
        print(f"\n{code}  ({len(hits)} finding(s))")
        print(f"  {why}")
        for f in hits:
            print(f"    {f['file']}:{f['line']}: {f['text']}")

    print("\n" + "=" * 70)
    print(f"total findings: {len(findings)}   new (not in baseline): {len(new)}")
    if args.new_only:
        if new:
            print("FAIL: new harness-lint findings.  Fix them, or suppress with")
            print("      '# harness-lint: ok - <reason>' if the instance is genuinely safe.")
            return 1
        print("PASS: no new harness-lint findings.")
        return 0
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())

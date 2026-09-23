#!/usr/bin/env python3
"""Offline audit of the ledger's CLOSED records for vacuous verification.

Why this exists
---------------
The ledger's bar is that a defect closes only on evidence that the test which
exercises the proven cause passed.  Across two sessions, six independent
harnesses were found reporting success for work that never happened -- an
unprepped fleet scored as failures, an assertion whose variable never expanded,
an ordering gate that opened early, three fault-injection matrices that injected
nothing and printed VERDICT PASS, a board chain that rendered the PREVIOUS DAY's
board after run.sh refused on the run lock, and a consecutive-streak harvest
that read `ls -dt ... | head -1` and would have scored the previous lap.

Every one of those produces fix-shaped evidence that measures nothing, and any
of them could have been cited to close a record.  So the closed side of the
ledger needs the same scrutiny as the open side: a closure resting on a log with
these signatures is not FIXED AND VERIFIED, whatever the log's last line says.

This tool spends NO rig time.  It reads the ledger, finds the evidence each
closed record cites, and scans those logs for the signatures.  It classifies
rather than concludes: a clean scan is a SCREENING result, not proof the
verification was sound, and the tool says so.  Absence of a signature is not
presence of a measurement.

Usage:  tools/closure_evidence_audit.py [--verbose] [--status STATUS]
"""
import argparse
import json
import os
import re
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LEDGER = os.path.join(REPO, "tests", "criteria", "OPEN_DEFECTS.json")

# Paths a record cites as its evidence.  BOTH forms matter and an early version
# of this tool followed only the first, which made 79 of 106 closed records look
# like they cited nothing at all.  In fact much closure evidence is a
# timestamped evidence DIRECTORY -- D-RECOV-ADVANCE-UNBOUNDED-RETRY closes on
# "chain 20 s439b, tests/evidence/20260829T045853Z_radv_takeover", and the two
# .log files it also names are superseded re-run attempts the record itself
# labels as such.  Following only .log paths therefore both overstated the
# unauditable fraction and pointed the audit at the wrong artifacts.
EVIDENCE_RE = re.compile(r"tests/evidence/[A-Za-z0-9_./-]+\.log")
EVIDENCE_DIR_CITE_RE = re.compile(r"tests/evidence/\d{8}T\d{6}Z[A-Za-z0-9_-]*")

TS_RE = re.compile(r"(\d{8}T\d{6}Z)")
ISO_RE = re.compile(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)")
EVID_DIR_RE = re.compile(r"EVIDENCE\s+tests/evidence/(board_\d{8}T\d{6}Z[A-Za-z0-9_]*)")

# A run that was refused never produced a result; anything printed after this
# describes a previous run.
REFUSAL = (
    "another run.sh holds",
    "clyde_preflight: FAIL",
    "ABORT:",
    "VACUOUS ARM",
)

# Counters that read zero mean the arm never reached the thing it was testing.
# Each is paired with the harness that emits it so a hit is actionable.
ZERO_WITNESS = (
    "P282=0",
    "iclus_marked=0",
    "iclus_unmarked=0",
    "entries=0 statted=0",
    "sum=0",
)
GOT_ZERO_RE = re.compile(r"got=0 want=[1-9]")
PASSY_RE = re.compile(r"VERDICT PASS|VERDICT: PASS|^\s*PASS\b", re.M)


def load_records():
    with open(LEDGER) as fh:
        doc = json.load(fh)
    recs = doc["defects"] if isinstance(doc, dict) and "defects" in doc else doc
    if isinstance(recs, dict):
        recs = list(recs.values())
    return recs


def cited_logs(rec):
    blob = " ".join(str(v) for v in rec.values())
    out = []
    for m in EVIDENCE_RE.finditer(blob):
        p = m.group(0)
        if p not in out:
            out.append(p)
    return out


def cited_dirs(rec):
    blob = " ".join(str(v) for v in rec.values())
    out = []
    for m in EVIDENCE_DIR_CITE_RE.finditer(blob):
        p = m.group(0)
        if p not in out and os.path.isdir(os.path.join(REPO, p)):
            out.append(p)
    return out


def scan_log(path):
    """Return (signatures, stats) for one evidence log."""
    full = os.path.join(REPO, path)
    sigs = []
    try:
        with open(full, "rb") as fh:
            raw = fh.read()
    except OSError:
        return ["MISSING_ARTIFACT"], {}
    text = raw.decode("utf-8", "replace")
    lines = text.splitlines()
    stats = {"bytes": len(raw), "lines": len(lines)}

    # -- signature: the chain finished within seconds of starting.  A board or
    # matrix that reports DONE almost immediately did no work; the s480a case
    # printed a full 28-PASS board one second after START.
    #
    # Parse the START and DONE lines SPECIFICALLY.  An earlier version of this
    # check took the first and last compact timestamp anywhere in the file and
    # flagged five records -- but chain logs write START/DONE in ISO form
    # (2026-08-29T12:39:54Z) and use the compact form (20260829T124123Z) only
    # inside evidence-DIRECTORY names, so it was measuring the gap between two
    # directory stamps and calling an 8-minute run instant.  A detector with a
    # vacuity bug of its own is exactly what this tool exists to catch, so it
    # now anchors on the lines that actually bound the run and reports
    # UNDATED_RUN when it cannot find them rather than guessing.
    t0 = t1 = None
    for ln in lines:
        m = ISO_RE.search(ln)
        if not m:
            continue
        if t0 is None and re.search(r"\b(START|start)\b", ln):
            t0 = m.group(1)
        if re.match(r"\s*DONE\b", ln):
            t1 = m.group(1)
    if t0 and t1:
        import datetime as dt

        fmt = "%Y-%m-%dT%H:%M:%SZ"
        span = (dt.datetime.strptime(t1, fmt) - dt.datetime.strptime(t0, fmt)).total_seconds()
        stats["span_s"] = int(span)
        if 0 <= span < 60 and PASSY_RE.search(text):
            sigs.append("INSTANT_DONE_WITH_PASS")
    else:
        stats["span_s"] = None

    # -- signature: the run was refused, yet the log still carries verdicts.
    #
    # Only an UNANNOTATED refusal counts.  A before/after chain deliberately
    # runs its pre-fix arm expecting failure and says so on the spot -- e.g.
    # sess430_s435.log carries "ABORT: test1 does not have an mxfs mount"
    # immediately followed by "STAGE ffr-prefix rc=2 (expected FAIL on 0.39.0:
    # the measurement)".  Flagging that as contamination is a false positive,
    # and a screening tool that cries wolf gets ignored, which costs more than
    # the misses.  So a refusal annotated as expected within two lines is
    # skipped.
    for token in REFUSAL:
        idx = text.find(token)
        if idx < 0:
            continue
        lineno = text.count("\n", 0, idx)
        window = " ".join(lines[lineno:lineno + 3]).lower()
        if "expected" in window or "by design" in window:
            break
        if PASSY_RE.search(text[idx:]):
            sigs.append("VERDICT_AFTER_REFUSAL:" + token.strip())
        else:
            sigs.append("REFUSAL_PRESENT:" + token.strip())
        break

    # -- signature: a zero injection/opportunity witness sitting next to a PASS.
    #
    # A `got=0 want=N` that the harness itself reported as a FAIL is the system
    # working: the gate fired and the run was scored down.  Only an unreported
    # one is evidence of a vacuous PASS.  Checking the line's own prefix, rather
    # than merely co-occurrence anywhere in the file, is what separates the two
    # -- sess433_chain4_0401_s433e.log:88 is "  FAIL B published exactly once
    # ... got=0 want=1" with STAGE rc=1, which is a correctly-reported failure
    # and not this defect class at all.
    if PASSY_RE.search(text):
        for w in ZERO_WITNESS:
            if w in text:
                sigs.append("ZERO_WITNESS_WITH_PASS:" + w)
        for ln in lines:
            if GOT_ZERO_RE.search(ln) and not re.match(r"\s*(FAIL|ERROR)\b", ln):
                sigs.append("GOT_ZERO_WANT_N_UNREPORTED")
                break

    # -- signature: streak/lap harvests reusing or back-dating an evidence dir.
    dirs = EVID_DIR_RE.findall(text)
    if dirs:
        stats["evidence_dirs"] = len(dirs)
        if len(set(dirs)) != len(dirs):
            sigs.append("EVIDENCE_DIR_REUSED")
        # An evidence directory older than the run that claims it belongs to a
        # PREVIOUS run.  Compare in the compact form the directory names use,
        # derived from the ISO START line rather than from another directory.
        if t0:
            start = t0.replace("-", "").replace(":", "")
            for d in dirs:
                m = TS_RE.search(d)
                if m and m.group(1) < start:
                    sigs.append("EVIDENCE_DIR_PREDATES_START")
                    break
    return sigs, stats


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("--status", default="FIXED AND VERIFIED")
    args = ap.parse_args()

    recs = [r for r in load_records() if r.get("status") == args.status]
    print(f"auditing {len(recs)} records with status '{args.status}'\n")

    buckets = {"NO_CITED_ARTIFACT": [], "SIGNATURE": [], "SCREENED_CLEAN": [], "DIR_EVIDENCE_ONLY": []}
    for rec in sorted(recs, key=lambda r: (r.get("severity", ""), r.get("id", ""))):
        rid = rec.get("id", "?")
        logs = cited_logs(rec)
        present = [p for p in logs if os.path.exists(os.path.join(REPO, p))]
        dirs = cited_dirs(rec)
        if not present and not dirs:
            buckets["NO_CITED_ARTIFACT"].append((rid, rec.get("severity"), len(logs)))
            continue
        if not present:
            # Evidence is a directory only.  Directories hold raw captures
            # (dmesg, knob readbacks) rather than a chain narrative, so the
            # log-shaped signatures do not apply; record it as auditable-by-hand
            # rather than pretending either a clean or a dirty screen.
            buckets["DIR_EVIDENCE_ONLY"].append((rid, rec.get("severity"), dirs))
            continue
        hits = []
        for p in present:
            sigs, stats = scan_log(p)
            if sigs:
                hits.append((p, sigs, stats))
        if hits:
            buckets["SIGNATURE"].append((rid, rec.get("severity"), hits))
        else:
            buckets["SCREENED_CLEAN"].append((rid, rec.get("severity"), len(present)))

    print("=" * 78)
    print("RECORDS WITH A VACUITY SIGNATURE IN CITED EVIDENCE")
    print("=" * 78)
    for rid, sev, hits in buckets["SIGNATURE"]:
        print(f"\n[{sev}] {rid}")
        for p, sigs, stats in hits:
            print(f"    {p}")
            print(f"      signatures: {', '.join(sigs)}")
            if args.verbose:
                print(f"      stats: {stats}")

    print("\n" + "=" * 78)
    print("RECORDS CITING NO EXISTING EVIDENCE LOG")
    print("(not necessarily contaminated -- but not auditable offline either,")
    print(" and under the closure bar an unverifiable closure is not verified)")
    print("=" * 78)
    for rid, sev, n in buckets["NO_CITED_ARTIFACT"]:
        print(f"  [{sev}] {rid}  (cited {n} log path(s), none present)")

    print("\n" + "=" * 78)
    print("SUMMARY")
    print("=" * 78)
    tot = len(recs)
    for k in ("SIGNATURE", "NO_CITED_ARTIFACT", "DIR_EVIDENCE_ONLY", "SCREENED_CLEAN"):
        n = len(buckets[k])
        print(f"  {k:<20} {n:4d}  ({100.0*n/tot if tot else 0:.1f}%)")
    print(
        "\n  SCREENED_CLEAN means no known signature was found in the cited logs."
        "\n  It is a screening result, NOT proof the verification exercised the"
        "\n  proven cause.  Absence of a signature is not presence of a measurement."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
